package filewatch

import (
	"context"

	"github.com/chrismfz/nxs/internal/logging"
)

// fallbackMonitor signals that real-time monitoring is unavailable.
// The daemon falls back to PeriodicScanner when Start returns a nil channel.
type fallbackMonitor struct {
	log *logging.Logger
}

func (m *fallbackMonitor) Start(_ context.Context) (<-chan string, error) {
	return nil, nil
}

func (m *fallbackMonitor) Stop() error { return nil }
