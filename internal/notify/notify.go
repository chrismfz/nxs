package notify

import (
	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/logging"
)

type Notifier interface {
	Notify(findings []*events.Finding) error
}

func New(cfg *config.Config, log *logging.Logger) Notifier {
	if !cfg.Notify.Enabled {
		return &nopNotifier{}
	}
	switch cfg.Notify.Method {
	case "sendmail":
		return &sendmailNotifier{cfg: cfg, log: log}
	case "smtp":
		return &smtpNotifier{cfg: cfg, log: log}
	case "slack":
		return &slackNotifier{cfg: cfg, log: log}
	default:
		return &nopNotifier{}
	}
}

type nopNotifier struct{}

func (n *nopNotifier) Notify(_ []*events.Finding) error { return nil }
