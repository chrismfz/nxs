package scanner

import (
	"github.com/chrismfz/nxs/internal/events"
)

func FilterBySeverity(in []*events.Finding, minSeverity string) []*events.Finding {
	out := in[:0]
	for _, f := range in {
		if events.MeetsSeverity(f.Severity, minSeverity) {
			out = append(out, f)
		}
	}
	return out
}

func FilterByPath(in []*events.Finding, prefix string) []*events.Finding {
	if prefix == "" {
		return in
	}
	out := in[:0]
	for _, f := range in {
		if len(f.Path) >= len(prefix) && f.Path[:len(prefix)] == prefix {
			out = append(out, f)
		}
	}
	return out
}
