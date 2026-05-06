package engine

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/exclusions"
	"github.com/chrismfz/nxs/internal/logging"
)

type Engine struct {
	cfg     *config.Config
	log     *logging.Logger
	hashIdx *HashIndex
	ac      *ACMatcher
	yara    *YARAScanner
	stats   atomicStats
	mu      sync.RWMutex
}

func New(cfg *config.Config, log *logging.Logger) (*Engine, error) {
	// Built-in hash DB (CSV format)
	idx, err := LoadHashDB(cfg.Engine.HashDB)
	if err != nil {
		log.Warn("hash DB load failed — continuing without it", "err", err)
		idx = &HashIndex{
			byMD5:    map[string]HashEntry{},
			bySHA1:   map[string]HashEntry{},
			bySHA256: map[string]HashEntry{},
		}
	}

	// Unified SIG_DIR: dispatch by extension
	var acSigs []Signature
	if cfg.Engine.SigDir != "" {
		entries, _ := os.ReadDir(cfg.Engine.SigDir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(cfg.Engine.SigDir, e.Name())
			switch ext := strings.ToLower(filepath.Ext(e.Name())); ext {
			case ".sig":
				more, err := parseSigFile(path)
				if err != nil {
					log.Warn("sig file load failed", "path", path, "err", err)
					continue
				}
				acSigs = append(acSigs, more...)
			case ".hdb", ".hsb":
				n, err := LoadClamAVHDB(path, idx)
				if err != nil {
					log.Warn("ClamAV hash DB load failed", "path", path, "err", err)
					continue
				}
				log.Info("loaded ClamAV hash DB", "path", path, "entries", n)
			case ".csv":
				// NXS CSV hash format — merge into existing index
				extra, err := LoadHashDB(path)
				if err != nil {
					log.Warn("CSV hash DB load failed", "path", path, "err", err)
					continue
				}
				for k, v := range extra.byMD5 {
					idx.byMD5[k] = v
				}
				for k, v := range extra.bySHA1 {
					idx.bySHA1[k] = v
				}
				for k, v := range extra.bySHA256 {
					idx.bySHA256[k] = v
				}
			// .yar/.yara are handled by YARAScanner below
			}
		}
	}

	ac := BuildACMatcher(acSigs)
	yara := NewYARAScanner(cfg, log)
	log.Info("engine loaded", "hashes", idx.Len(), "signatures", len(acSigs), "yara", yara.Enabled())

	e := &Engine{cfg: cfg, log: log, hashIdx: idx, ac: ac, yara: yara}
	e.stats.reset()
	return e, nil
}

// ScanFile scans a single file and returns any findings.
func (e *Engine) ScanFile(path string) ([]*events.Finding, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		e.stats.filesSkipped.Add(1)
		return nil, nil
	}
	if info.Size() > e.cfg.Engine.MaxFileSizeBytes {
		e.stats.filesSkipped.Add(1)
		return nil, nil
	}

	e.stats.filesScanned.Add(1)

	md5sum, sha1sum, sha256sum, err := HashFile(path)
	if err != nil {
		return nil, err
	}

	// Tier 1: hash lookup (MD5, SHA1, SHA256)
	for _, h := range []string{md5sum, sha1sum, sha256sum} {
		if entry, ok := e.hashIdx.Lookup(h); ok {
			e.stats.hashHits.Add(1)
			f := events.NewFinding("engine", "hash", entry.Severity, entry.Kind,
				"malware hash match: "+entry.Label)
			f.Path = path
			f.Evidence = map[string]any{
				"md5":       md5sum,
				"sha1":      sha1sum,
				"sha256":    sha256sum,
				"signature": entry.Label,
				"algorithm": entry.Algorithm,
			}
			e.stats.findingsEmitted.Add(1)
			return []*events.Finding{f}, nil
		}
	}

	// Tier 2: Aho-Corasick pattern scan
	data, err := readFile(path, e.cfg.Engine.MaxFileSizeBytes)
	if err != nil {
		return nil, err
	}

	hitIdxs := e.ac.Match(data)

	// Tier 3: YARA-X subprocess scan (runs regardless of Tier 2 result)
	if e.yara.Enabled() {
		yaraFindings, err := e.yara.ScanFile(path)
		if err != nil {
			e.log.Warn("yara scan error", "path", path, "err", err)
		}
		if len(yaraFindings) > 0 {
			for _, f := range yaraFindings {
				f.Evidence["md5"] = md5sum
				f.Evidence["sha1"] = sha1sum
				f.Evidence["sha256"] = sha256sum
				e.stats.findingsEmitted.Add(1)
			}
			// Return combined: YARA findings take precedence over AC findings
			// for the same file (both sets are returned).
			if len(hitIdxs) == 0 {
				return yaraFindings, nil
			}
		}
	}

	if len(hitIdxs) == 0 {
		return nil, nil
	}

	// Deduplicate by signature ID and build findings.
	seen := make(map[string]bool)
	var findings []*events.Finding
	for _, idx := range hitIdxs {
		sig := e.ac.Sig(idx)
		if seen[sig.ID] {
			continue
		}
		seen[sig.ID] = true
		e.stats.patternHits.Add(1)

		// find approximate offset of the match
		off := int64(0)
		for i := range data {
			if i+len(sig.Pattern) <= len(data) {
				match := true
				for j, b := range sig.Pattern {
					if data[i+j] != b {
						match = false
						break
					}
				}
				if match {
					off = int64(i)
					break
				}
			}
		}

		samples := events.ExtractSamples(path, []int64{off}, e.cfg.Samples.MaxSamplesPerFinding)
		f := events.NewFinding("engine", "pattern", sig.Severity, sig.Kind,
			"pattern match: "+sig.ID)
		f.Path = path
		f.Samples = samples
		f.Evidence = map[string]any{
			"signature": sig.ID,
			"md5":       md5sum,
			"sha1":      sha1sum,
			"sha256":    sha256sum,
		}
		findings = append(findings, f)
		e.stats.findingsEmitted.Add(1)
	}
	return findings, nil
}

// ScanDir walks root and emits findings on the returned channel.
func (e *Engine) ScanDir(ctx context.Context, root string, excls *exclusions.ExclusionSet) (<-chan *events.Finding, error) {
	ch := make(chan *events.Finding, 256)
	go func() {
		defer close(ch)
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() {
				if excluded, _ := excls.MatchPath(path); excluded {
					return filepath.SkipDir
				}
				return nil
			}
			if excluded, hint := excls.MatchPath(path); excluded {
				_ = hint
				return nil
			}
			if !shouldScan(path, e.cfg) {
				return nil
			}
			findings, err := e.ScanFile(path)
			if err != nil {
				return nil
			}
			for _, f := range findings {
				select {
				case ch <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}()
	return ch, nil
}

func (e *Engine) Stats() Stats {
	return e.stats.snapshot()
}

func (e *Engine) ResetStats() {
	e.stats.reset()
}

func shouldScan(path string, cfg *config.Config) bool {
	ext := filepath.Ext(path)
	if len(cfg.Scanner.WatchExtensions) == 0 {
		return true
	}
	for _, allowed := range cfg.Scanner.WatchExtensions {
		if ext == allowed {
			return true
		}
	}
	return false
}

func readFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxBytes))
}
