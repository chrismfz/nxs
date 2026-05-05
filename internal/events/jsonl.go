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

type JSONLWriter struct {
	path string
	f    *os.File
	w    *bufio.Writer
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	return &JSONLWriter{path: path, f: f, w: bufio.NewWriter(f)}, nil
}

func (jw *JSONLWriter) Write(f *Finding) error {
	RedactFinding(f)
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	// Acquire exclusive lock only for the duration of this write so multiple
	// processes (daemon + CLI scan) can share the log file safely.
	if err := syscall.Flock(int(jw.f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("findings log flock: %w", err)
	}
	jw.w.Write(b)
	jw.w.WriteByte('\n')
	flushErr := jw.w.Flush()
	syncErr := jw.f.Sync()
	_ = syscall.Flock(int(jw.f.Fd()), syscall.LOCK_UN)
	if flushErr != nil {
		return flushErr
	}
	return syncErr
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
