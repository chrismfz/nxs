package exclusions

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func List(path string) ([]*Exclusion, error) {
	s, err := Load(path)
	if err != nil {
		return nil, err
	}
	return s.items, nil
}

func Add(path string, exclType ExclusionType, value, component, kind, reason string) (*Exclusion, error) {
	s, err := Load(path)
	if err != nil {
		return nil, err
	}
	e := &Exclusion{
		ID:        newExclID(),
		Type:      exclType,
		Value:     value,
		Component: component,
		Kind:      kind,
		Reason:    reason,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	s.items = append(s.items, e)
	if err := flush(path, s.items); err != nil {
		return nil, err
	}
	return e, nil
}

func Remove(path, id string) error {
	s, err := Load(path)
	if err != nil {
		return err
	}
	filtered := s.items[:0]
	found := false
	for _, e := range s.items {
		if e.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !found {
		return fmt.Errorf("exclusion %q not found", id)
	}
	return flush(path, filtered)
}

func flush(path string, items []*Exclusion) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newExclID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "exc_" + hex.EncodeToString(b)
}
