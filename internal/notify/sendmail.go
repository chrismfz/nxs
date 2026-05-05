package notify

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/logging"
)

type sendmailNotifier struct {
	cfg *config.Config
	log *logging.Logger
}

func (n *sendmailNotifier) Notify(findings []*events.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	if len(n.cfg.Notify.To) == 0 {
		return fmt.Errorf("notify: no recipients configured")
	}

	hostname := findings[0].Hostname
	subject := buildSubject(findings, hostname)
	body := buildBody(findings)
	msg := buildEmail(n.cfg.Notify.From, n.cfg.Notify.To, subject, body)

	path := n.cfg.Notify.SendmailPath
	if path == "" {
		path = "/usr/sbin/sendmail"
	}

	cmd := exec.Command(path, "-t")
	cmd.Stdin = strings.NewReader(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sendmail: %w: %s", err, out)
	}
	n.log.Info("notification sent via sendmail", "findings", len(findings), "to", n.cfg.Notify.To)
	return nil
}
