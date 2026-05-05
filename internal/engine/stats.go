package engine

import (
	"sync/atomic"
	"time"
)

type Stats struct {
	FilesScanned    uint64
	FilesSkipped    uint64
	FindingsEmitted uint64
	HashHits        uint64
	PatternHits     uint64
	StartTime       time.Time
}

type atomicStats struct {
	filesScanned    atomic.Uint64
	filesSkipped    atomic.Uint64
	findingsEmitted atomic.Uint64
	hashHits        atomic.Uint64
	patternHits     atomic.Uint64
	startTime       time.Time
}

func (a *atomicStats) snapshot() Stats {
	return Stats{
		FilesScanned:    a.filesScanned.Load(),
		FilesSkipped:    a.filesSkipped.Load(),
		FindingsEmitted: a.findingsEmitted.Load(),
		HashHits:        a.hashHits.Load(),
		PatternHits:     a.patternHits.Load(),
		StartTime:       a.startTime,
	}
}

func (a *atomicStats) reset() {
	a.filesScanned.Store(0)
	a.filesSkipped.Store(0)
	a.findingsEmitted.Store(0)
	a.hashHits.Store(0)
	a.patternHits.Store(0)
	a.startTime = time.Now()
}
