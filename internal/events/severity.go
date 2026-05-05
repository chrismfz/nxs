package events

import "fmt"

var severityRanks = map[string]int{
	SevCritical: 5,
	SevHigh:     4,
	SevMedium:   3,
	SevLow:      2,
	SevInfo:     1,
}

func ParseSeverity(s string) (string, error) {
	if _, ok := severityRanks[s]; ok {
		return s, nil
	}
	return "", fmt.Errorf("unknown severity %q (valid: critical,high,medium,low,info)", s)
}

func SeverityRank(s string) int {
	if r, ok := severityRanks[s]; ok {
		return r
	}
	return 0
}

func MeetsSeverity(finding, minimum string) bool {
	return SeverityRank(finding) >= SeverityRank(minimum)
}
