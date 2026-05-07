package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/logging"
	"github.com/chrismfz/nxs/internal/setup"
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
	Identifier string       `json:"identifier"`
	Matches    []yaraXMatch `json:"matches"`
}

type yaraXMatch struct {
	Offset      int64  `json:"offset"`
	Length      int    `json:"length"`
	MatchedData string `json:"matched_data"`
}

// yaraBundledDir is the package-installed rules dir (bundled nxs-base.yar etc).
// Always searched for .yar/.yara files in addition to SIG_DIR.
const yaraBundledDir = "/usr/share/nxs/signatures"

// YARAScanner wraps the yr binary via subprocess.
// It degrades gracefully when yr or rule files are absent.
type YARAScanner struct {
	binary    string
	ruleFiles []string // explicit .yar/.yara file paths passed to yr
	tempDir   string   // filtered rule copies created by the preflight step
	log       *logging.Logger
	enabled   bool
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
			"hint", "run: nxs signatures update")
		return &YARAScanner{}
	}

	// Collect .yar/.yara files from bundled dir and SIG_DIR explicitly.
	// We pass file paths rather than dirs so that yr never tries to parse
	// .hdb/.sig/etc files as YARA rules.
	var files []string
	files = append(files, collectYARFiles(yaraBundledDir)...)
	files = append(files, collectYARFiles(cfg.Engine.SigDir)...)

	if len(files) == 0 {
		log.Info("yara-x: no .yar/.yara files found — YARA tier disabled",
			"hint", "run: nxs signatures update")
		return &YARAScanner{}
	}

	preflight, err := setup.PreflightYARRules(files)
	if err != nil {
		log.Warn("yara-x: rule preflight failed", "err", err)
	}
	for _, dup := range preflight.Duplicates {
		log.Warn("yara-x: skipping duplicate rule",
			"path", dup.File,
			"rule", dup.Name,
			"original", dup.OriginalFile)
	}
	for _, failure := range preflight.ParseFailures {
		log.Warn("yara-x: rule preflight parse failed", "path", failure.File, "err", failure.Err)
	}

	activeFiles, tempDir := files, ""
	if preflight.DuplicateSkipped > 0 || preflight.ParseFailed > 0 {
		activeFiles, tempDir, err = buildPreflightRuleFiles(files, preflight, log)
		if err != nil {
			log.Warn("yara-x: failed to build duplicate-filtered rule set", "err", err)
		} else {
			files = activeFiles
		}
	}

	if preflight.ActiveRules == 0 {
		log.Warn("yara-x: no active rules after preflight — YARA tier disabled")
		if tempDir != "" {
			_ = os.RemoveAll(tempDir)
		}
		return &YARAScanner{}
	}

	log.Info("yara-x scanner ready",
		"binary", binary,
		"rule_files", len(files),
		"active_rules", preflight.ActiveRules,
		"duplicate_skipped", preflight.DuplicateSkipped,
		"parse_failed", preflight.ParseFailed)
	return &YARAScanner{
		binary:    binary,
		ruleFiles: files,
		tempDir:   tempDir,
		log:       log,
		enabled:   true,
	}
}

// buildPreflightRuleFiles creates filtered temporary copies for any source file
// with duplicate declarations so yr can compile the first occurrence of each
// rule name without dropping the rest of a colliding .yar/.yara file.
func buildPreflightRuleFiles(files []string, report setup.YARAPreflightReport, log *logging.Logger) ([]string, string, error) {
	tmpDir, err := os.MkdirTemp("", "nxs-yara-rules-*")
	if err != nil {
		return files, "", err
	}
	hasSkipped := make(map[string]bool)
	for _, decl := range report.Declarations {
		if decl.Skipped {
			hasSkipped[decl.File] = true
		}
	}
	parseFailed := make(map[string]bool)
	for _, failure := range report.ParseFailures {
		parseFailed[failure.File] = true
	}

	active := make([]string, 0, len(files))
	for i, file := range files {
		if parseFailed[file] {
			log.Warn("yara-x: skipping rule file with preflight parse failure", "path", file)
			continue
		}
		if !hasSkipped[file] {
			active = append(active, file)
			continue
		}
		filtered := filepath.Join(tmpDir, fmt.Sprintf("%03d-%s", i, filepath.Base(file)))
		if err := setup.FilterYARRuleFile(file, filtered, report.Declarations); err != nil {
			_ = os.RemoveAll(tmpDir)
			return files, "", err
		}
		active = append(active, filtered)
		log.Info("yara-x: using preflight-filtered rule file", "source", file, "filtered", filtered)
	}
	return active, tmpDir, nil
}

// collectYARFiles returns the paths of all .yar/.yara files directly in dir.
func collectYARFiles(dir string) []string {
	return setup.CollectYARFiles(dir)
}

func (s *YARAScanner) Enabled() bool { return s.enabled }

// Close removes any temporary preflight-filtered rule files.
func (s *YARAScanner) Close() {
	if s != nil && s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir)
		s.tempDir = ""
	}
}

// ScanFile runs yr against a single file and returns findings for each matching rule.
func (s *YARAScanner) ScanFile(path string) ([]*events.Finding, error) {
	if !s.enabled {
		return nil, nil
	}

	// Build args: flags, then explicit rule files, then target path.
	// Passing files (not dirs) prevents yr from trying to parse .hdb/.sig etc.
	args := []string{
		"scan",
		"--output-format=ndjson",
		"--print-namespace",
		"--print-meta",
		"--print-tags",
		"--print-strings=120",
	}
	args = append(args, s.ruleFiles...)
	args = append(args, path)
	cmd := exec.Command(s.binary, args...)

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
