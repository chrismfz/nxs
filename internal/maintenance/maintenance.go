package maintenance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Window struct {
	Name      string    `json:"name"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Schedule struct {
	path    string
	windows []*Window
}

func Load(path string) (*Schedule, error) {
	s := &Schedule{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &s.windows); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Schedule) InMaintenance(t time.Time) (bool, string) {
	if s == nil {
		return false, ""
	}
	for _, w := range s.windows {
		if !t.Before(w.Start) && t.Before(w.End) {
			return true, w.Name
		}
	}
	return false, ""
}

func (s *Schedule) Windows() []*Window {
	if s == nil {
		return nil
	}
	return s.windows
}

func (s *Schedule) Add(w *Window) error {
	s.windows = append(s.windows, w)
	return s.flush()
}

func AddWindow(path string, w *Window) error {
	s, err := Load(path)
	if err != nil {
		return err
	}
	w.CreatedAt = time.Now().UTC()
	return s.Add(w)
}

func RemoveWindow(path, name string) error {
	s, err := Load(path)
	if err != nil {
		return err
	}
	filtered := s.windows[:0]
	found := false
	for _, w := range s.windows {
		if w.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, w)
	}
	if !found {
		return fmt.Errorf("maintenance window %q not found", name)
	}
	s.windows = filtered
	return s.flush()
}

func (s *Schedule) flush() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.windows, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
