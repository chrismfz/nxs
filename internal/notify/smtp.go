package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/logging"
)

type smtpNotifier struct {
	cfg *config.Config
	log *logging.Logger
}

func (n *smtpNotifier) Notify(findings []*events.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	cfg := n.cfg.Notify
	if cfg.SMTPHost == "" {
		return fmt.Errorf("smtp: SMTP_HOST not configured")
	}

	hostname := findings[0].Hostname
	subject := buildSubject(findings, hostname)
	body := buildBody(findings)
	msg := buildEmail(cfg.From, cfg.To, subject, body)

	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)

	var c *smtp.Client
	var err error

	if cfg.SMTPPort == 465 {
		// Implicit TLS
		tlsCfg := &tls.Config{ServerName: cfg.SMTPHost}
		conn, err2 := tls.Dial("tcp", addr, tlsCfg)
		if err2 != nil {
			return fmt.Errorf("smtp tls dial: %w", err2)
		}
		c, err = smtp.NewClient(conn, cfg.SMTPHost)
	} else {
		c, err = smtp.Dial(addr)
		if cfg.SMTPPort == 587 && err == nil {
			// STARTTLS
			tlsCfg := &tls.Config{ServerName: cfg.SMTPHost}
			if err = c.StartTLS(tlsCfg); err != nil {
				c.Close()
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("smtp connect: %w", err)
	}
	defer c.Close()

	if cfg.SMTPUser != "" {
		host, _, _ := net.SplitHostPort(addr)
		auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, to := range cfg.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", to, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := fmt.Fprint(wc, msg); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	n.log.Info("notification sent via smtp", "findings", len(findings), "host", cfg.SMTPHost)
	return c.Quit()
}

func init() { _ = strings.Contains } // keep import
