package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/logging"
)

type slackNotifier struct {
	cfg *config.Config
	log *logging.Logger
}

func (n *slackNotifier) Notify(findings []*events.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	if n.cfg.Notify.SlackWebhook == "" {
		return fmt.Errorf("slack: SLACK_WEBHOOK not configured")
	}

	text := buildSlackText(findings)
	payload, _ := json.Marshal(map[string]string{"text": text})

	resp, err := http.Post(n.cfg.Notify.SlackWebhook, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("slack webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	n.log.Info("notification sent via slack", "findings", len(findings))
	return nil
}

func buildSlackText(findings []*events.Finding) string {
	var sb strings.Builder
	for sev, label := range map[string]string{
		events.SevCritical: ":rotating_light: *CRITICAL*",
		events.SevHigh:     ":warning: *HIGH*",
		events.SevMedium:   ":large_yellow_circle: *MEDIUM*",
	} {
		var group []*events.Finding
		for _, f := range findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "%s findings on `%s`:\n", label, group[0].Hostname)
		for _, f := range group {
			line := fmt.Sprintf("• `%s` — %s", f.Kind, f.Message)
			if f.Path != "" {
				line += fmt.Sprintf(" (`%s`)", f.Path)
			}
			sb.WriteString(line + "\n")
		}
	}
	return sb.String()
}
