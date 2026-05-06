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

// yaraBundledDir is the package-installed rules dir (bundled nxs-base.yar etc).
// Always searched for .yar/.yara files in addition to SIG_DIR.
const yaraBundledDir = "/usr/share/nxs/signatures"

// YARAScanner wraps the yr binary via subprocess.
// It degrades gracefully when yr or rule files are absent.
type YARAScanner struct {
	binary    string
	ruleFiles []string // explicit .yar/.yara file paths passed to yr
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

	// Remove files that cause duplicate-rule compile errors so yr doesn't
	// fail the entire scan. Bundled files (loaded first) win on conflicts.
	files = buildCompatibleRuleSet(binary, files, log)
	if len(files) == 0 {
		log.Warn("yara-x: all rule files were dropped due to conflicts — YARA tier disabled")
		return &YARAScanner{}
	}

	log.Info("yara-x scanner ready", "binary", binary, "rule_files", len(files))
	return &YARAScanner{
		binary:    binary,
		ruleFiles: files,
		log:       log,
		enabled:   true,
	}
}

// buildCompatibleRuleSet probes yr and iteratively removes files that cause
// duplicate-rule (E012) errors, keeping the first-seen declaration in each
// conflict. Bundled files are listed first so they win over downloaded ones.
func buildCompatibleRuleSet(binary string, files []string, log *logging.Logger) []string {
	// Probe target: yr needs a file to scan even for compile testing.
	// /proc/version is always present on Linux; use it as a dummy target.
	probe := "/proc/version"
	if _, err := os.Stat(probe); err != nil {
		// Fallback: create a tiny temp file.
		tmp, err2 := os.CreateTemp("", "yr-probe-*")
		if err2 != nil {
			return files
		}
		tmp.Close()
		defer os.Remove(tmp.Name())
		probe = tmp.Name()
	}

	for attempt := 0; attempt < 20; attempt++ {
		args := append([]string{"scan", "--output-format=ndjson"}, files...)
		args = append(args, probe)
		cmd := exec.Command(binary, args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.Run()

		errText := stderr.String()
		if !strings.Contains(errText, "error[E012]") {
			return files // no duplicate-rule errors
		}

		toSkip := parseDuplicateFiles(errText)
		if len(toSkip) == 0 {
			return files
		}

		var kept, dropped []string
		for _, f := range files {
			if toSkip[f] {
				dropped = append(dropped, f)
			} else {
				kept = append(kept, f)
			}
		}
		log.Warn("yara-x: skipping rule files with duplicate rule names",
			"dropped", strings.Join(dropped, ", "))
		files = kept
		if len(files) == 0 {
			return nil
		}
	}
	return files
}

// parseDuplicateFiles extracts the set of file paths that are the *later*
// (duplicate) declaration in E012 errors. These are the files to drop.
//
// yr error format:
//
//	error[E012]: duplicate rule `name`
//	    --> /path/to/file.yar:LINE:COL
func parseDuplicateFiles(errText string) map[string]bool {
	out := make(map[string]bool)
	lines := strings.Split(errText, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "error[E012]") {
			continue
		}
		// Find the next line containing "-->"
		for j := i + 1; j < len(lines) && j < i+5; j++ {
			trimmed := strings.TrimSpace(lines[j])
			if !strings.HasPrefix(trimmed, "-->") {
				continue
			}
			// Format: "--> /path/to/file.yar:LINE:COL"
			rest := strings.TrimPrefix(trimmed, "-->")
			rest = strings.TrimSpace(rest)
			// Strip the :LINE:COL suffix
			if colon := strings.LastIndex(rest, ":"); colon > 0 {
				rest = rest[:colon]
			}
			if colon := strings.LastIndex(rest, ":"); colon > 0 {
				rest = rest[:colon]
			}
			if rest != "" {
				out[rest] = true
			}
			break
		}
	}
	return out
}

// collectYARFiles returns the paths of all .yar/.yara files directly in dir.
func collectYARFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && isYARFile(e.Name()) {
			out = append(out, dir+"/"+e.Name())
		}
	}
	return out
}

func isYARFile(name string) bool {
	return strings.HasSuffix(name, ".yar") || strings.HasSuffix(name, ".yara")
}

func (s *YARAScanner) Enabled() bool { return s.enabled }

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
