package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Main struct {
	Enabled  bool
	Hostname string
	DataDir  string
	LogDir   string
	RunDir   string
}

type Findings struct {
	LogPath          string
	StatePath        string
	Notify           bool
	NotifyMinSev     string
	NotifyCooldown   string
}

type Samples struct {
	MaxDiffLines        int
	MaxLineLength       int
	MaxSamplesPerFinding int
	RedactSecrets       bool
	URLDefang           bool
}

type Engine struct {
	Enabled          bool
	SigDir           string // unified: .yar/.yara/.hdb/.hsb/.sig/.csv all go here
	HashDB           string
	YARAEnabled      bool
	YARABinary       string // path to yr binary; default "yr"
	ClamdEnabled     bool
	ClamdSocket      string
	ClamdTimeout     string
	ClamdFallback    bool
	MaxFileSizeBytes int64
}

type Scanner struct {
	Enabled           bool
	FanotifyEnabled   bool
	WatchPaths        []string
	PeriodicEnabled   bool
	PeriodicEvery     string
	PeriodicStartHour int
	WatchExtensions   []string
	MaxFileSize       int64
	QuarantineDir     string
	AutoClean         bool
	QueueSize         int
	MaxWorkers        int
}

type Quarantine struct {
	Dir  string
	Mode string // chmod, copy, move
}

type Notify struct {
	Enabled         bool
	Method          string // sendmail, smtp, slack, none
	SendmailPath    string
	To              []string
	From            string
	SMTPHost        string
	SMTPPort        int
	SMTPUser        string
	SMTPPass        string
	SlackWebhook    string
	DefaultCooldown string
	MinSeverity     string
}

type Exclusions struct {
	File string
}

type Maintenance struct {
	StatePath string
}

type CFM struct {
	Enabled  bool
	APIURL   string
	APIToken string
	BlockTTL string
	BlockOn  []string
}

type Config struct {
	Main        Main
	Findings    Findings
	Samples     Samples
	Engine      Engine
	Scanner     Scanner
	Quarantine  Quarantine
	Notify      Notify
	Exclusions  Exclusions
	Maintenance Maintenance
	CFM         CFM
}

func Default() *Config {
	return &Config{
		Main: Main{
			Enabled: true,
			DataDir: "/var/lib/nxs",
			LogDir:  "/var/log/nxs",
			RunDir:  "/var/run/nxs",
		},
		Findings: Findings{
			LogPath:      "/var/log/nxs/findings.log",
			StatePath:    "/var/lib/nxs/state/findings.json",
			Notify:       true,
			NotifyMinSev: "high",
		},
		Samples: Samples{
			MaxDiffLines:         20,
			MaxLineLength:        300,
			MaxSamplesPerFinding: 10,
			RedactSecrets:        true,
			URLDefang:            true,
		},
		Engine: Engine{
			Enabled:          true,
			SigDir:           "/var/lib/nxs/signatures",
			HashDB:           "/usr/share/nxs/hashdb.csv",
			MaxFileSizeBytes: 10 * 1024 * 1024,
			YARABinary:       "yr",
			ClamdSocket:      "/var/run/clamav/clamd.sock",
			ClamdTimeout:     "10s",
		},
		Scanner: Scanner{
			Enabled:         true,
			FanotifyEnabled: true,
			WatchPaths:      []string{"/home", "/tmp", "/dev/shm"},
			PeriodicEnabled: true,
			PeriodicEvery:   "6h",
			WatchExtensions: []string{".php", ".phtml", ".php5", ".php7", ".html", ".htm", ".js", ".htaccess", ".user.ini"},
			MaxFileSize:     2 * 1024 * 1024,
			QuarantineDir:   "/var/lib/nxs/quarantine",
			QueueSize:       1024,
			MaxWorkers:      4,
		},
		Quarantine: Quarantine{
			Dir:  "/var/lib/nxs/quarantine",
			Mode: "chmod",
		},
		Notify: Notify{
			Enabled:         true,
			Method:          "sendmail",
			SendmailPath:    "/usr/sbin/sendmail",
			DefaultCooldown: "30m",
			MinSeverity:     "high",
		},
		Exclusions: Exclusions{
			File: "/var/lib/nxs/state/exclusions.json",
		},
		Maintenance: Maintenance{
			StatePath: "/var/lib/nxs/state/maintenance.json",
		},
		CFM: CFM{
			BlockTTL: "24h",
			BlockOn:  []string{"webshell", "dropper", "rootkit_artifact", "binary_tampered"},
		},
	}
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()

	cfg := Default()
	section := ""

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(strings.ToLower(k))
		v = strings.TrimSpace(v)
		// strip inline comment
		if idx := strings.Index(v, " #"); idx >= 0 {
			v = strings.TrimSpace(v[:idx])
		}

		applyKey(cfg, section, k, v)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return cfg, nil
}

func applyKey(cfg *Config, section, k, v string) {
	switch section {
	case "main":
		switch k {
		case "enabled":
			cfg.Main.Enabled = parseBool(v)
		case "hostname":
			cfg.Main.Hostname = v
		case "data_dir":
			cfg.Main.DataDir = v
		case "log_dir":
			cfg.Main.LogDir = v
		case "run_dir":
			cfg.Main.RunDir = v
		}

	case "findings":
		switch k {
		case "log_path":
			cfg.Findings.LogPath = v
		case "state_path":
			cfg.Findings.StatePath = v
		case "notify":
			cfg.Findings.Notify = parseBool(v)
		case "notify_min_severity":
			cfg.Findings.NotifyMinSev = v
		case "notify_cooldown":
			cfg.Findings.NotifyCooldown = v
		}

	case "samples":
		switch k {
		case "max_diff_lines":
			cfg.Samples.MaxDiffLines = parseInt(v, cfg.Samples.MaxDiffLines)
		case "max_line_length":
			cfg.Samples.MaxLineLength = parseInt(v, cfg.Samples.MaxLineLength)
		case "max_samples_per_finding":
			cfg.Samples.MaxSamplesPerFinding = parseInt(v, cfg.Samples.MaxSamplesPerFinding)
		case "redact_secrets":
			cfg.Samples.RedactSecrets = parseBool(v)
		case "url_defang":
			cfg.Samples.URLDefang = parseBool(v)
		}

	case "engine":
		switch k {
		case "enabled":
			cfg.Engine.Enabled = parseBool(v)
		case "sig_dir":
			cfg.Engine.SigDir = v
		case "hash_db":
			cfg.Engine.HashDB = v
		case "yara_enabled":
			cfg.Engine.YARAEnabled = parseBool(v)
		case "yara_binary":
			cfg.Engine.YARABinary = v
		case "clamd_enabled":
			cfg.Engine.ClamdEnabled = parseBool(v)
		case "clamd_socket":
			cfg.Engine.ClamdSocket = v
		case "clamd_timeout":
			cfg.Engine.ClamdTimeout = v
		case "clamd_fallback_only":
			cfg.Engine.ClamdFallback = parseBool(v)
		case "max_file_size":
			cfg.Engine.MaxFileSizeBytes = parseInt64(v, cfg.Engine.MaxFileSizeBytes)
		}

	case "scanner":
		switch k {
		case "enabled":
			cfg.Scanner.Enabled = parseBool(v)
		case "fanotify_enabled":
			cfg.Scanner.FanotifyEnabled = parseBool(v)
		case "watch_paths":
			cfg.Scanner.WatchPaths = splitComma(v)
		case "periodic_enabled":
			cfg.Scanner.PeriodicEnabled = parseBool(v)
		case "periodic_every":
			cfg.Scanner.PeriodicEvery = v
		case "periodic_start_hour":
			cfg.Scanner.PeriodicStartHour = parseInt(v, cfg.Scanner.PeriodicStartHour)
		case "watch_extensions":
			cfg.Scanner.WatchExtensions = splitComma(v)
		case "max_file_size":
			cfg.Scanner.MaxFileSize = parseInt64(v, cfg.Scanner.MaxFileSize)
		case "quarantine_dir":
			cfg.Scanner.QuarantineDir = v
		case "auto_clean":
			cfg.Scanner.AutoClean = parseBool(v)
		case "queue_size":
			cfg.Scanner.QueueSize = parseInt(v, cfg.Scanner.QueueSize)
		case "max_workers":
			cfg.Scanner.MaxWorkers = parseInt(v, cfg.Scanner.MaxWorkers)
		}

	case "quarantine":
		switch k {
		case "dir":
			cfg.Quarantine.Dir = v
		case "mode":
			cfg.Quarantine.Mode = v
		}

	case "notify":
		switch k {
		case "enabled":
			cfg.Notify.Enabled = parseBool(v)
		case "method":
			cfg.Notify.Method = v
		case "sendmail_path":
			cfg.Notify.SendmailPath = v
		case "to":
			cfg.Notify.To = splitComma(v)
		case "from":
			cfg.Notify.From = v
		case "smtp_host":
			cfg.Notify.SMTPHost = v
		case "smtp_port":
			cfg.Notify.SMTPPort = parseInt(v, cfg.Notify.SMTPPort)
		case "smtp_user":
			cfg.Notify.SMTPUser = v
		case "smtp_pass":
			cfg.Notify.SMTPPass = v
		case "slack_webhook":
			cfg.Notify.SlackWebhook = v
		case "default_cooldown":
			cfg.Notify.DefaultCooldown = v
		case "min_severity":
			cfg.Notify.MinSeverity = v
		}

	case "exclusions":
		switch k {
		case "file":
			cfg.Exclusions.File = v
		}

	case "maintenance":
		switch k {
		case "state_path":
			cfg.Maintenance.StatePath = v
		}

	case "cfm":
		switch k {
		case "enabled":
			cfg.CFM.Enabled = parseBool(v)
		case "api_url":
			cfg.CFM.APIURL = v
		case "api_token":
			cfg.CFM.APIToken = v
		case "block_ttl":
			cfg.CFM.BlockTTL = v
		case "block_on":
			cfg.CFM.BlockOn = splitComma(v)
		}
	}
}

func parseBool(v string) bool {
	v = strings.ToLower(v)
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func parseInt(v string, def int) int {
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func parseInt64(v string, def int64) int64 {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func splitComma(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
