package engine

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

// WatchReload listens for SIGHUP and reloads signatures + hash DB.
func (e *Engine) WatchReload(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			e.log.Info("SIGHUP received — reloading engine")
			if err := e.reload(); err != nil {
				e.log.Error("engine reload failed", "err", err)
			} else {
				e.log.Info("engine reloaded", "hashes", e.hashIdx.Len(), "sigs", len(e.ac.sigs))
			}
		}
	}
}

func (e *Engine) reload() error {
	idx, err := LoadHashDB(e.cfg.Engine.HashDB)
	if err != nil {
		e.log.Warn("hash DB load failed — continuing without it", "err", err)
		idx = &HashIndex{
			byMD5:    map[string]HashEntry{},
			bySHA1:   map[string]HashEntry{},
			bySHA256: map[string]HashEntry{},
		}
	}

	var acSigs []Signature
	if e.cfg.Engine.SigDir != "" {
		entries, _ := os.ReadDir(e.cfg.Engine.SigDir)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(e.cfg.Engine.SigDir, entry.Name())
			switch ext := strings.ToLower(filepath.Ext(entry.Name())); ext {
			case ".sig":
				more, err := parseSigFile(path)
				if err != nil {
					e.log.Warn("sig file load failed", "path", path, "err", err)
					continue
				}
				acSigs = append(acSigs, more...)
			case ".ndb":
				more, loaded, skipped, err := LoadNDB(path)
				if err != nil {
					e.log.Warn("NDB load failed", "path", path, "err", err)
					continue
				}
				acSigs = append(acSigs, more...)
				e.log.Info("loaded NDB", "path", path, "loaded", loaded, "skipped_wildcards", skipped)
			case ".hdb", ".hsb":
				n, err := LoadClamAVHDB(path, idx)
				if err != nil {
					e.log.Warn("ClamAV hash DB load failed", "path", path, "err", err)
					continue
				}
				e.log.Info("loaded ClamAV hash DB", "path", path, "entries", n)
			case ".csv":
				extra, err := LoadHashDB(path)
				if err != nil {
					e.log.Warn("CSV hash DB load failed", "path", path, "err", err)
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
			}
		}
	}

	yara := NewYARAScanner(e.cfg, e.log)

	e.mu.Lock()
	oldYARA := e.yara
	e.hashIdx = idx
	e.ac = BuildACMatcher(acSigs)
	e.yara = yara
	e.mu.Unlock()
	if oldYARA != nil {
		oldYARA.Close()
	}
	return nil
}
