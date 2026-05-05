package events

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// Severity levels.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// Finding kinds.
const (
	KindMalware    = "malware"
	KindSuspicious = "suspicious"
	KindModified   = "modified"
	KindQuarantined = "quarantined"
	KindError      = "error"
	KindInfo       = "info"
)

type Sample struct {
	Type    string `json:"type"`
	Path    string `json:"path,omitempty"`
	LineNo  int    `json:"line_no,omitempty"`
	Content string `json:"content,omitempty"`
	Hash    string `json:"hash,omitempty"`
}

type Diff struct {
	Added   []Sample `json:"added,omitempty"`
	Removed []Sample `json:"removed,omitempty"`
	Changed []Sample `json:"changed,omitempty"`
}

type Finding struct {
	ID       string    `json:"id"`
	TS       time.Time `json:"ts"`
	Hostname string    `json:"hostname"`

	Component string `json:"component"`
	Source    string `json:"source"`
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`

	Message string `json:"message"`

	Path  string `json:"path,omitempty"`
	PID   int    `json:"pid,omitempty"`
	PPID  int    `json:"ppid,omitempty"`
	UID   int    `json:"uid,omitempty"`
	GID   int    `json:"gid,omitempty"`
	User  string `json:"user,omitempty"`
	Group string `json:"group,omitempty"`

	Evidence map[string]any `json:"evidence,omitempty"`
	Samples  []Sample       `json:"samples,omitempty"`
	Diff     *Diff          `json:"diff,omitempty"`

	Action       string `json:"action,omitempty"`
	ActionResult string `json:"action_result,omitempty"`

	CFMBlockAttempted bool   `json:"cfm_block_attempted,omitempty"`
	CFMBlockResult    string `json:"cfm_block_result,omitempty"`

	ExcludeHint string `json:"exclude_hint,omitempty"`

	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Count     int       `json:"count,omitempty"`

	Suppressed            bool      `json:"suppressed,omitempty"`
	SuppressReason        string    `json:"suppress_reason,omitempty"`
	MaintenanceSuppressed bool      `json:"maintenance_suppressed,omitempty"`
	NotifyEligible        bool      `json:"notify_eligible,omitempty"`
	NotifiedAt            time.Time `json:"notified_at,omitempty"`
}

func NewFinding(component, source, severity, kind, message string) *Finding {
	now := time.Now().UTC()
	hostname, _ := os.Hostname()
	return &Finding{
		ID:        newID(component),
		TS:        now,
		Hostname:  hostname,
		Component: component,
		Source:    source,
		Severity:  severity,
		Kind:      kind,
		Message:   message,
		FirstSeen: now,
		LastSeen:  now,
		Count:     1,
	}
}

func newID(component string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s-%d", component, hex.EncodeToString(b), time.Now().UnixNano()%1e6)
}
