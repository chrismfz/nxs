package scanner

import (
	"context"
	"time"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/logging"
)

type PeriodicScanner struct {
	pipeline *Pipeline
	cfg      *config.Config
	log      *logging.Logger
	trigger  chan struct{}
}

func NewPeriodic(pipeline *Pipeline, cfg *config.Config, log *logging.Logger) *PeriodicScanner {
	return &PeriodicScanner{
		pipeline: pipeline,
		cfg:      cfg,
		log:      log,
		trigger:  make(chan struct{}, 1),
	}
}

// Start runs the periodic scanner goroutine. Returns when ctx is cancelled.
func (s *PeriodicScanner) Start(ctx context.Context) {
	interval, err := time.ParseDuration(s.cfg.Scanner.PeriodicEvery)
	if err != nil {
		interval = 6 * time.Hour
	}

	s.log.Info("periodic scanner started", "interval", interval)
	timer := time.NewTimer(10 * time.Second) // first run shortly after start
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("periodic scanner stopped")
			return
		case <-s.trigger:
			timer.Reset(0)
		case <-timer.C:
			s.runScan(ctx)
			timer.Reset(interval)
		}
	}
}

func (s *PeriodicScanner) TriggerNow() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *PeriodicScanner) runScan(ctx context.Context) {
	roots := s.cfg.Scanner.WatchPaths
	s.log.Info("periodic scan starting", "roots", roots)
	start := time.Now()

	findings, err := s.pipeline.RunScan(ctx, roots)
	if err != nil {
		s.log.Error("periodic scan error", "err", err)
		return
	}

	s.log.Info("periodic scan complete",
		"duration", time.Since(start).Round(time.Second),
		"notify_eligible", len(findings),
	)
}
