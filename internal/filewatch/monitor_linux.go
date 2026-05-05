//go:build linux

package filewatch

import (
	"context"
	"syscall"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/logging"
)

type fanotifyMonitor struct {
	cfg *config.Config
	log *logging.Logger
}

func newPlatformMonitor(cfg *config.Config, log *logging.Logger) Monitor {
	// Probe fanotify availability at construction time.
	fd, _, errno := syscall.Syscall(syscall.SYS_FANOTIFY_INIT, 0, 0, 0)
	if errno == syscall.ENOSYS || errno == syscall.EPERM {
		log.Info("fanotify unavailable — will use periodic scan",
			"reason", errno.Error())
		return &fallbackMonitor{log: log}
	}
	if fd != ^uintptr(0) {
		syscall.Close(int(fd))
	}
	// fanotify available but deferred to post-beta.
	log.Info("fanotify available — real-time monitoring deferred to post-beta; using periodic scan")
	return &fallbackMonitor{log: log}
}

func (m *fanotifyMonitor) Start(_ context.Context) (<-chan string, error) {
	return nil, nil
}

func (m *fanotifyMonitor) Stop() error { return nil }
