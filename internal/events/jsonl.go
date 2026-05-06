package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// JSONLWriter appends findings to a JSONL log.
//
// Mutual exclusion between the daemon and concurrent `nxs scan` processes is
// handled via a per-write advisory lock on a sidecar .lock file.  The lock is
// held only for the duration of each Write call so that multiple processes can
// coexist without blocking each other at open time.
type JSONLWriter struct {
	path     string
	lockPath string
	f        *os.File
	w        *bufio.Writer
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	return &JSONLWriter{
		path:     path,
		lockPath: path + ".lock",
		f:        f,
		w:        bufio.NewWriter(f),
	}, nil
}

func (jw *JSONLWriter) Write(f *Finding) error {
	RedactFinding(f)
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}

	lf, err := os.OpenFile(jw.lockPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("findings lock: %w", err)
	}
	defer lf.Close()

	// Blocking lock — wait for other writers to finish, then proceed.
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("findings lock acquire: %w", err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) //nolint:errcheck

	jw.w.Write(b)
	jw.w.WriteByte('\n')
	if err := jw.w.Flush(); err != nil {
		return err
	}
	return jw.f.Sync()
}

func (jw *JSONLWriter) Close() error {
	return jw.f.Close()
}

func (jw *JSONLWriter) ReadAll() ([]*Finding, error) {
	return ReadFindings(jw.path, time.Time{}, "", 0)
}

func (jw *JSONLWriter) ReadFiltered(since time.Time, severity string, limit int) ([]*Finding, error) {
	return ReadFindings(jw.path, since, severity, limit)
}

// ReadFindings reads findings from a JSONL file (read-only, no lock needed).
func ReadFindings(path string, since time.Time, minSeverity string, limit int) ([]*Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []*Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var fn Finding
		if err := json.Unmarshal(line, &fn); err != nil {
			continue
		}
		if !since.IsZero() && fn.TS.Before(since) {
			continue
		}
		if minSeverity != "" && !MeetsSeverity(fn.Severity, minSeverity) {
			continue
		}
		out = append(out, &fn)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, sc.Err()
}
