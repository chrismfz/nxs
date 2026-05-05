package exclusions

import (
	"encoding/json"
	"os"
	"time"
)

type ExclusionType string

const (
	ExclPath      ExclusionType = "path"
	ExclPrefix    ExclusionType = "prefix"
	ExclGlob      ExclusionType = "glob"
	ExclHash      ExclusionType = "hash"
	ExclFindingID ExclusionType = "finding_id"
	ExclRegex     ExclusionType = "regex"
)

type Exclusion struct {
	ID        string        `json:"id"`
	Type      ExclusionType `json:"type"`
	Value     string        `json:"value"`
	Component string        `json:"component,omitempty"`
	Kind      string        `json:"kind,omitempty"`
	Reason    string        `json:"reason,omitempty"`
	Enabled   bool          `json:"enabled"`
	CreatedAt time.Time     `json:"created_at"`
}

func Load(path string) (*ExclusionSet, error) {
	s := &ExclusionSet{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &s.items); err != nil {
		return nil, err
	}
	return s, nil
}
