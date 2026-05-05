package scanner

import "github.com/chrismfz/nxs/internal/events"

// DedupFindings removes duplicate findings within a single scan run,
// keyed by path + kind + source.
func DedupFindings(in []*events.Finding) []*events.Finding {
	seen := make(map[string]bool)
	out := make([]*events.Finding, 0, len(in))
	for _, f := range in {
		key := f.Path + "|" + f.Kind + "|" + f.Source
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
