package filewatch

import (
	"strings"

	"github.com/chrismfz/nxs/internal/config"
)

// FilterPath returns true if the path should be passed to the scanner.
func FilterPath(path string, cfg *config.Config) bool {
	// Skip virtual/special filesystems
	for _, skip := range []string{"/proc/", "/sys/", "/dev/", "/run/"} {
		if strings.HasPrefix(path, skip) {
			return false
		}
	}
	// Check watch roots
	for _, root := range cfg.Scanner.WatchPaths {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
}
