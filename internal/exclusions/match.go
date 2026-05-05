package exclusions

import (
	"path/filepath"
	"regexp"
	"strings"
)

type ExclusionSet struct {
	path  string
	items []*Exclusion
}

func (s *ExclusionSet) Items() []*Exclusion {
	if s == nil {
		return nil
	}
	return s.items
}

func (s *ExclusionSet) MatchPath(path string) (bool, string) {
	if s == nil {
		return false, ""
	}
	for _, e := range s.items {
		if !e.Enabled {
			continue
		}
		switch e.Type {
		case ExclPath:
			if path == e.Value {
				return true, e.ID
			}
		case ExclPrefix:
			if strings.HasPrefix(path, e.Value) {
				return true, e.ID
			}
		case ExclGlob:
			if ok, _ := filepath.Match(e.Value, path); ok {
				return true, e.ID
			}
		case ExclRegex:
			if ok, _ := regexp.MatchString(e.Value, path); ok {
				return true, e.ID
			}
		}
	}
	return false, ""
}

func (s *ExclusionSet) MatchHash(hash string) (bool, string) {
	if s == nil {
		return false, ""
	}
	for _, e := range s.items {
		if !e.Enabled {
			continue
		}
		if e.Type == ExclHash && strings.EqualFold(e.Value, hash) {
			return true, e.ID
		}
	}
	return false, ""
}

func (s *ExclusionSet) MatchFindingID(id string) (bool, string) {
	if s == nil {
		return false, ""
	}
	for _, e := range s.items {
		if !e.Enabled {
			continue
		}
		if e.Type == ExclFindingID && e.Value == id {
			return true, e.ID
		}
	}
	return false, ""
}
