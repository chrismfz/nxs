package notify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/chrismfz/nxs/internal/events"
)

type notifyRecord struct {
	NotifiedAt time.Time `json:"notified_at"`
}

type NotifyStateStore struct {
	path    string
	records map[string]notifyRecord
	cooldown time.Duration
}

func NewNotifyStateStore(stateDir string, cooldown time.Duration) (*NotifyStateStore, error) {
	path := filepath.Join(stateDir, "notified.state")
	s := &NotifyStateStore{
		path:     path,
		records:  make(map[string]notifyRecord),
		cooldown: cooldown,
	}
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &s.records)
	}
	return s, nil
}

func (s *NotifyStateStore) ShouldNotify(f *events.Finding) bool {
	rec, ok := s.records[f.ID]
	if !ok {
		return true
	}
	return time.Since(rec.NotifiedAt) >= s.cooldown
}

func (s *NotifyStateStore) MarkNotified(id string) error {
	s.records[id] = notifyRecord{NotifiedAt: time.Now().UTC()}
	return s.flush()
}

func (s *NotifyStateStore) flush() error {
	b, err := json.Marshal(s.records)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
