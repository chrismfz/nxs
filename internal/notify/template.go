package notify

import (
	"fmt"
	"strings"

	"github.com/chrismfz/nxs/internal/events"
)

func buildSubject(findings []*events.Finding, hostname string) string {
	if len(findings) == 1 {
		f := findings[0]
		return fmt.Sprintf("[NXS] [%s] %s on %s", strings.ToUpper(f.Severity), f.Kind, hostname)
	}
	return fmt.Sprintf("[NXS] %d findings on %s", len(findings), hostname)
}

func buildBody(findings []*events.Finding) string {
	var sb strings.Builder
	for i, f := range findings {
		if i > 0 {
			sb.WriteString("\n---\n\n")
		}
		fmt.Fprintf(&sb, "Severity:  %s\n", f.Severity)
		fmt.Fprintf(&sb, "Kind:      %s\n", f.Kind)
		fmt.Fprintf(&sb, "Component: %s\n", f.Component)
		fmt.Fprintf(&sb, "Time:      %s\n", f.TS.Format("2006-01-02 15:04:05 UTC"))
		fmt.Fprintf(&sb, "Host:      %s\n", f.Hostname)
		if f.Path != "" {
			fmt.Fprintf(&sb, "Path:      %s\n", f.Path)
		}
		if f.Message != "" {
			fmt.Fprintf(&sb, "Message:   %s\n", f.Message)
		}
		if f.Action != "" {
			fmt.Fprintf(&sb, "Action:    %s (%s)\n", f.Action, f.ActionResult)
		}
		if f.ExcludeHint != "" {
			fmt.Fprintf(&sb, "\nTo exclude this finding:\n  nxs exclusions add --field path --equals %s --reason \"...\"\n", f.Path)
		}
		if len(f.Samples) > 0 {
			sb.WriteString("\nSamples:\n")
			for _, s := range f.Samples {
				fmt.Fprintf(&sb, "  [%s] %s\n", s.Type, s.Content)
			}
		}
	}
	return sb.String()
}

func buildEmail(from string, to []string, subject, body string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "From: %s\r\n", from)
	fmt.Fprintf(&sb, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&sb, "Subject: %s\r\n", subject)
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}
