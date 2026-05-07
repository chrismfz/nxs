package engine

import (
	"context"
	"fmt"
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
			case ".ndb":
				more, loaded, skipped, err := LoadNDB(path)
				if err != nil {
					log.Warn("NDB load failed", "path", path, "err", err)
					continue
				}
				acSigs = append(acSigs, more...)
				log.Info("loaded NDB", "path", path, "loaded", loaded, "skipped_wildcards", skipped)
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

// Close releases engine-owned resources such as temporary YARA preflight files.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.yara != nil {
		e.yara.Close()
	}
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

	// Tier 0: executable binary detection (ELF / PE magic bytes).
	// Collected here and merged with results from later tiers so the file is
	// also checked against hash DBs and YARA rules.
	var findings []*events.Finding
	for _, f := range detectExecutable(path, info) {
		findings = append(findings, f)
		e.stats.findingsEmitted.Add(1)
	}

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
			findings = append(findings, f)
			// Hash match is definitive — skip AC/YARA for this file.
			return findings, nil
		}
	}

	// Tier 2: Aho-Corasick pattern scan
	data, err := readFile(path, e.cfg.Engine.MaxFileSizeBytes)
	if err != nil {
		return findings, err
	}
	hitIdxs := e.ac.Match(data)

	// Tier 3: YARA-X subprocess scan (runs regardless of Tier 2 result)
	if e.yara.Enabled() {
		yaraFindings, err := e.yara.ScanFile(path)
		if err != nil {
			e.log.Warn("yara scan error", "path", path, "err", err)
		}
		for _, f := range yaraFindings {
			f.Evidence["md5"] = md5sum
			f.Evidence["sha1"] = sha1sum
			f.Evidence["sha256"] = sha256sum
			e.stats.findingsEmitted.Add(1)
			findings = append(findings, f)
		}
	}

	// Deduplicate AC hits by signature ID and append findings.
	seen := make(map[string]bool)
	for _, idx := range hitIdxs {
		sig := e.ac.Sig(idx)
		if seen[sig.ID] {
			continue
		}
		seen[sig.ID] = true
		e.stats.patternHits.Add(1)

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

	if len(findings) == 0 {
		return nil, nil
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
			if !shouldScan(path, d, e.cfg) {
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

// detectExecutable checks the first 4 bytes for ELF/PE magic and returns a
// finding if the file is an executable binary. Called before extension filtering
// so no executable slips through regardless of its name or extension.
func detectExecutable(path string, info os.FileInfo) []*events.Finding {
	if info.Size() < 4 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return nil
	}

	var kind, label string
	switch {
	case magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		kind = "suspicious_executable"
		label = "ELF binary"
	case magic[0] == 'M' && magic[1] == 'Z':
		kind = "suspicious_executable"
		label = "PE/Windows executable"
	default:
		return nil
	}

	finding := events.NewFinding("engine", "magic", events.SevHigh, kind,
		label+" found in scan path: "+path)
	finding.Path = path
	finding.Evidence = map[string]any{
		"magic": fmt.Sprintf("%02x%02x%02x%02x", magic[0], magic[1], magic[2], magic[3]),
		"size":  info.Size(),
		"mode":  info.Mode().String(),
		"label": label,
	}
	return []*events.Finding{finding}
}

func shouldScan(path string, d os.DirEntry, cfg *config.Config) bool {
	ext := filepath.Ext(path)
	if len(cfg.Scanner.WatchExtensions) == 0 {
		return true
	}
	for _, allowed := range cfg.Scanner.WatchExtensions {
		if ext == allowed {
			return true
		}
	}
	// Always scan files with executable bits regardless of extension —
	// catches ELF/PE binaries dropped without a recognisable extension.
	if info, err := d.Info(); err == nil && info.Mode()&0111 != 0 {
		return true
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
