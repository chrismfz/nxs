package scanner

import (
	"context"
	"time"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/engine"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/exclusions"
	"github.com/chrismfz/nxs/internal/logging"
	"github.com/chrismfz/nxs/internal/maintenance"
)

type Pipeline struct {
	cfg    *config.Config
	log    *logging.Logger
	eng    *engine.Engine
	quar   *Quarantine
	state  *events.StateStore
	excls  *exclusions.ExclusionSet
	sched  *maintenance.Schedule
	writer *events.JSONLWriter
}

func NewPipeline(cfg *config.Config, log *logging.Logger) (*Pipeline, error) {
	eng, err := engine.New(cfg, log)
	if err != nil {
		return nil, err
	}
	quar, err := NewQuarantine(cfg, log)
	if err != nil {
		return nil, err
	}
	state, err := events.NewStateStore(cfg.Findings.StatePath)
	if err != nil {
		log.Warn("state store init failed — dedup disabled", "err", err)
		state, _ = events.NewStateStore("")
	}
	excls, err := exclusions.Load(cfg.Exclusions.File)
	if err != nil {
		log.Warn("exclusions load failed — running without exclusions", "err", err)
		excls = nil
	}
	sched, err := maintenance.Load(cfg.Maintenance.StatePath)
	if err != nil {
		log.Warn("maintenance schedule load failed", "err", err)
		sched = nil
	}
	writer, err := events.NewJSONLWriter(cfg.Findings.LogPath)
	if err != nil {
		return nil, err
	}
	return &Pipeline{
		cfg:    cfg,
		log:    log,
		eng:    eng,
		quar:   quar,
		state:  state,
		excls:  excls,
		sched:  sched,
		writer: writer,
	}, nil
}

func (p *Pipeline) Close() {
	if p.eng != nil {
		p.eng.Close()
	}
	if p.writer != nil {
		_ = p.writer.Close()
	}
	if p.state != nil {
		_ = p.state.Flush()
	}
}

// RunScan scans all roots and returns notify-eligible findings.
func (p *Pipeline) RunScan(ctx context.Context, roots []string) ([]*events.Finding, error) {
	now := time.Now()
	if inMaint, window := p.sched.InMaintenance(now); inMaint {
		p.log.Info("skipping scan — maintenance window active", "window", window)
		return nil, nil
	}

	var notify []*events.Finding

	for _, root := range roots {
		ch, err := p.eng.ScanDir(ctx, root, p.excls)
		if err != nil {
			p.log.Error("ScanDir failed", "root", root, "err", err)
			continue
		}
		for f := range ch {
			if ctx.Err() != nil {
				return notify, ctx.Err()
			}
			p.processFinding(f, now, &notify)
		}
	}

	if err := p.state.Flush(); err != nil {
		p.log.Warn("state flush failed", "err", err)
	}

	return notify, nil
}

// ProcessFinding handles a single finding from any source (engine, integrity, runtime).
func (p *Pipeline) ProcessFinding(f *events.Finding) {
	var dummy []*events.Finding
	p.processFinding(f, time.Now(), &dummy)
	_ = p.state.Flush()
}

func (p *Pipeline) processFinding(f *events.Finding, now time.Time, notify *[]*events.Finding) {
	// Exclusion check
	if p.excls != nil {
		if excluded, hint := p.excls.MatchPath(f.Path); excluded {
			f.Suppressed = true
			f.SuppressReason = "exclusion:" + hint
			f.ExcludeHint = hint
		}
		if !f.Suppressed && f.Evidence != nil {
			if sha, ok := f.Evidence["sha256"].(string); ok {
				if excluded, hint := p.excls.MatchHash(sha); excluded {
					f.Suppressed = true
					f.SuppressReason = "exclusion:" + hint
				}
			}
		}
	}

	// Maintenance check
	if !f.Suppressed {
		if inMaint, window := p.sched.InMaintenance(now); inMaint {
			f.MaintenanceSuppressed = true
			f.SuppressReason = "maintenance:" + window
		}
	}

	// State store: dedup
	if prev, ok := p.state.Seen(f.ID); ok {
		f.FirstSeen = prev.FirstSeen
		f.Count = prev.Count + 1
	}
	p.state.Record(f.ID, now)
	f.LastSeen = now

	// Action decision
	if !f.Suppressed && !f.MaintenanceSuppressed {
		if Decide(f, p.cfg) == ActionQuarantined {
			if err := p.quar.Quarantine(f.Path, f); err != nil {
				p.log.Error("quarantine failed", "path", f.Path, "err", err)
				f.ActionResult = "failed: " + err.Error()
			}
		}
	}

	// Write to JSONL
	if err := p.writer.Write(f); err != nil {
		p.log.Error("findings write failed", "err", err)
	}

	// Mark notify-eligible: new finding (Count==1 after increment), not suppressed
	if f.Count <= 1 && !f.Suppressed && !f.MaintenanceSuppressed {
		if events.MeetsSeverity(f.Severity, p.cfg.Findings.NotifyMinSev) {
			f.NotifyEligible = true
			*notify = append(*notify, f)
		}
	}
}

func (p *Pipeline) Engine() *engine.Engine { return p.eng }
