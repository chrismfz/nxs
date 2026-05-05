package filewatch

import (
	"context"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/logging"
)

// Monitor provides a channel of filesystem paths to scan.
// A nil channel means the monitor is unavailable; fall back to periodic scan.
type Monitor interface {
	Start(ctx context.Context) (<-chan string, error)
	Stop() error
}

// New returns the platform-appropriate monitor.
func New(cfg *config.Config, log *logging.Logger) Monitor {
	return newPlatformMonitor(cfg, log)
}
