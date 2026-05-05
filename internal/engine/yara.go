package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/logging"
)

// yaraXResult is one NDJSON line from `yr scan --output-format=ndjson`.
type yaraXResult struct {
	Path  string      `json:"path"`
	Rules []yaraXRule `json:"rules"`
}

type yaraXRule struct {
	Identifier string         `json:"identifier"`
	Namespace  string         `json:"namespace"`
	Tags       []string       `json:"tags"`
	Metadata   map[string]any `json:"metadata"`
	Patterns   []yaraXPattern `json:"patterns"`
}

type yaraXPattern struct {
	Identifier string        `json:"identifier"`
	Matches    []yaraXMatch  `json:"matches"`
}

type yaraXMatch struct {
	Offset      int64  `json:"offset"`
	Length      int    `json:"length"`
	MatchedData string `json:"matched_data"`
}

// YARAScanner wraps the yr binary via subprocess.
// It degrades gracefully when yr or the rules dir is absent.
type YARAScanner struct {
	binary   string
	rulesDir string
	log      *logging.Logger
	enabled  bool
}

func NewYARAScanner(cfg *config.Config, log *logging.Logger) *YARAScanner {
	if !cfg.Engine.YARAEnabled {
		return &YARAScanner{}
	}

	binary := cfg.Engine.YARABinary
	if binary == "" {
		binary = "yr"
	}
	if _, err := exec.LookPath(binary); err != nil {
		log.Info("yara-x binary not found — YARA tier disabled",
			"binary", binary,
			"hint", "install yara-x: https://github.com/VirusTotal/yara-x")
		return &YARAScanner{}
	}

	rulesDir := cfg.Engine.YARARulesDir
	if rulesDir == "" {
		log.Warn("yara-x: YARA_RULES_DIR not set — YARA tier disabled")
		return &YARAScanner{}
	}
	if _, err := os.Stat(rulesDir); err != nil {
		log.Warn("yara-x: rules dir not found — YARA tier disabled", "dir", rulesDir)
		return &YARAScanner{}
	}

	log.Info("yara-x scanner ready", "binary", binary, "rules_dir", rulesDir)
	return &YARAScanner{
		binary:   binary,
		rulesDir: rulesDir,
		log:      log,
		enabled:  true,
	}
}

func (s *YARAScanner) Enabled() bool { return s.enabled }

// ScanFile runs yr against a single file and returns findings for each matching rule.
func (s *YARAScanner) ScanFile(path string) ([]*events.Finding, error) {
	if !s.enabled {
		return nil, nil
	}

	cmd := exec.Command(s.binary, "scan",
		"--output-format=ndjson",
		"--print-namespace",
		"--print-meta",
		"--print-tags",
		"--print-strings=120",
		s.rulesDir,
		path,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run() // yr may exit non-zero on match; we check output instead

	if errText := strings.TrimSpace(stderr.String()); errText != "" {
		// Only warn on real errors (rule compile failures, missing files, etc.)
		// yr writes warnings to stderr for things like deprecated syntax.
		if strings.Contains(errText, "error") {
			s.log.Warn("yara-x stderr", "path", path, "stderr", errText)
		}
	}

	if stdout.Len() == 0 {
		return nil, nil // no matches
	}

	return s.parseNDJSON(stdout.Bytes())
}

func (s *YARAScanner) parseNDJSON(data []byte) ([]*events.Finding, error) {
	var findings []*events.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var result yaraXResult
		if err := json.Unmarshal(line, &result); err != nil {
			s.log.Warn("yara-x: failed to parse output line", "err", err)
			continue
		}
		for _, rule := range result.Rules {
			findings = append(findings, s.ruleToFinding(result.Path, rule))
		}
	}
	return findings, sc.Err()
}

func (s *YARAScanner) ruleToFinding(path string, rule yaraXRule) *events.Finding {
	severity := yaraMetaString(rule.Metadata, "severity", "threat_level", "level")
	severity = normalizeYARASeverity(severity)

	description := yaraMetaString(rule.Metadata, "description", "desc", "reference")
	if description == "" {
		description = rule.Identifier
	}

	f := events.NewFinding("engine", "yara-x", severity, events.KindMalware,
		"YARA-X match: "+description)
	f.Path = path

	ev := map[string]any{
		"rule":      rule.Identifier,
		"namespace": rule.Namespace,
	}
	if len(rule.Tags) > 0 {
		ev["tags"] = strings.Join(rule.Tags, ",")
	}
	for k, v := range rule.Metadata {
		kl := strings.ToLower(k)
		// Skip credential-like metadata keys
		if strings.ContainsAny(kl, "") {
			_ = kl
		}
		ev["meta_"+k] = fmt.Sprintf("%v", v)
	}
	f.Evidence = ev

	// Convert pattern matches to samples (safe — these are already byte snippets)
	for _, pat := range rule.Patterns {
		for _, m := range pat.Matches {
			if m.MatchedData != "" {
				f.Samples = append(f.Samples, events.Sample{
					Type:    "yara",
					Path:    path,
					Content: m.MatchedData,
					Hash:    fmt.Sprintf("offset=%d len=%d", m.Offset, m.Length),
				})
			}
		}
	}

	return f
}

// yaraMetaString returns the first non-empty string value for any of the given keys.
func yaraMetaString(meta map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := meta[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// normalizeYARASeverity maps YARA Forge / custom metadata severity strings to NXS levels.
func normalizeYARASeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "5", "very_high":
		return events.SevCritical
	case "high", "4":
		return events.SevHigh
	case "medium", "3", "moderate":
		return events.SevMedium
	case "low", "2":
		return events.SevLow
	case "info", "1", "informational":
		return events.SevInfo
	default:
		// YARA Forge typically uses high for malware rules
		return events.SevHigh
	}
}
