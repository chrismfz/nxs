package engine

import (
	"context"
	"os"
	"os/signal"
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
		return err
	}
	sigs, err := LoadSigDir(e.cfg.Engine.SigDir)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.hashIdx = idx
	e.ac = BuildACMatcher(sigs)
	e.mu.Unlock()
	return nil
}
