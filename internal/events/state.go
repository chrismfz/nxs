package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type FindingState struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

type StateStore struct {
	path  string
	index map[string]FindingState
}

func NewStateStore(stateFile string) (*StateStore, error) {
	s := &StateStore{
		path:  stateFile,
		index: make(map[string]FindingState),
	}
	if err := os.MkdirAll(filepath.Dir(stateFile), 0755); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(stateFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &s.index)
	}
	return s, nil
}

func (s *StateStore) Seen(id string) (FindingState, bool) {
	st, ok := s.index[id]
	return st, ok
}

func (s *StateStore) Record(id string, ts time.Time) {
	st, ok := s.index[id]
	if !ok {
		st = FindingState{FirstSeen: ts}
	}
	st.LastSeen = ts
	st.Count++
	s.index[id] = st
}

func (s *StateStore) Flush() error {
	b, err := json.Marshal(s.index)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
