package scanner

import (
	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
)

type ActionResult string

const (
	ActionQuarantined ActionResult = "quarantined"
	ActionSkipped     ActionResult = "skipped"
	ActionFailed      ActionResult = "failed"
)

// Decide returns the action to take based on finding severity and config.
// critical/high findings are quarantined when AUTO_CLEAN is enabled.
func Decide(f *events.Finding, cfg *config.Config) ActionResult {
	if !cfg.Scanner.AutoClean {
		return ActionSkipped
	}
	switch f.Severity {
	case events.SevCritical, events.SevHigh:
		return ActionQuarantined
	default:
		return ActionSkipped
	}
}
