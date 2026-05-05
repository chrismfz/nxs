//go:build !linux

package filewatch

import (
	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/logging"
)

func newPlatformMonitor(cfg *config.Config, log *logging.Logger) Monitor {
	log.Info("fanotify not available on this platform — using periodic scan")
	return &fallbackMonitor{log: log}
}
