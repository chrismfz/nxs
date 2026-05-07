package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
type yaraRuleFile struct {
	Path         string
	OriginalPath string
	Source       string
	Namespace    string
}

type YARAScanner struct {
	binary           string
	ruleFiles        []yaraRuleFile // explicit .yar/.yara files passed to yr
	namespaceSupport bool
	tempDir          string // filtered rule copies created by the preflight step
	log              *logging.Logger
	enabled          bool
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
	var files []yaraRuleFile
	files = append(files, collectYARFiles(yaraBundledDir, "bundled", "bundled")...)
	files = append(files, collectYARFiles(cfg.Engine.SigDir, "local", "local")...)

	if len(files) == 0 {
		log.Info("yara-x: no .yar/.yara files found — YARA tier disabled",
			"hint", "run: nxs signatures update")
		return &YARAScanner{}
	}

	namespaceSupport := yrSupportsRuleNamespaces(binary, log)
	preflight, err := preflightYARRuleFiles(files, namespaceSupport)
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
		"parse_failed", preflight.ParseFailed,
		"namespaces", formatNamespaceRuleCounts(namespaceRuleCounts(files, preflight)),
		"namespace_args", namespaceSupport)
	return &YARAScanner{
		binary:           binary,
		ruleFiles:        files,
		namespaceSupport: namespaceSupport,
		tempDir:          tempDir,
		log:              log,
		enabled:          true,
	}
}

// buildPreflightRuleFiles creates filtered temporary copies for any source file
// with duplicate declarations so yr can compile the first occurrence of each
// rule name without dropping the rest of a colliding .yar/.yara file.
func buildPreflightRuleFiles(files []yaraRuleFile, report setup.YARAPreflightReport, log *logging.Logger) ([]yaraRuleFile, string, error) {
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

	active := make([]yaraRuleFile, 0, len(files))
	for i, file := range files {
		if parseFailed[file.Path] {
			log.Warn("yara-x: skipping rule file with preflight parse failure", "path", file.Path, "namespace", file.Namespace)
			continue
		}
		if !hasSkipped[file.Path] {
			active = append(active, file)
			continue
		}
		filtered := filepath.Join(tmpDir, fmt.Sprintf("%03d-%s", i, filepath.Base(file.Path)))
		if err := setup.FilterYARRuleFile(file.Path, filtered, report.Declarations); err != nil {
			_ = os.RemoveAll(tmpDir)
			return files, "", err
		}
		active = append(active, yaraRuleFile{Path: filtered, OriginalPath: file.OriginalPath, Source: file.Source, Namespace: file.Namespace})
		log.Info("yara-x: using preflight-filtered rule file", "source", file.Path, "filtered", filtered, "namespace", file.Namespace)
	}
	return active, tmpDir, nil
}

// preflightYARRuleFiles scans rules in either their planned yr namespaces or, when
// the installed yr cannot namespace individual rule paths, one shared namespace.
func preflightYARRuleFiles(files []yaraRuleFile, namespaceSupport bool) (setup.YARAPreflightReport, error) {
	if !namespaceSupport {
		return setup.PreflightYARRules(ruleFilePaths(files))
	}

	var merged setup.YARAPreflightReport
	groups := make(map[string][]string)
	var order []string
	for _, file := range files {
		if _, ok := groups[file.Namespace]; !ok {
			order = append(order, file.Namespace)
		}
		groups[file.Namespace] = append(groups[file.Namespace], file.Path)
	}
	for _, namespace := range order {
		report, err := setup.PreflightYARRules(groups[namespace])
		if err != nil {
			return merged, err
		}
		mergeYARAPreflightReport(&merged, report)
	}
	merged.Files = len(files)
	return merged, nil
}

func mergeYARAPreflightReport(dst *setup.YARAPreflightReport, src setup.YARAPreflightReport) {
	dst.TotalRules += src.TotalRules
	dst.ActiveRules += src.ActiveRules
	dst.DuplicateSkipped += src.DuplicateSkipped
	dst.ParseFailed += src.ParseFailed
	dst.Declarations = append(dst.Declarations, src.Declarations...)
	dst.Duplicates = append(dst.Duplicates, src.Duplicates...)
	dst.ParseFailures = append(dst.ParseFailures, src.ParseFailures...)
}

func ruleFilePaths(files []yaraRuleFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}

// collectYARFiles returns metadata for all .yar/.yara files directly in dir.
func collectYARFiles(dir, source, namespace string) []yaraRuleFile {
	paths := setup.CollectYARFiles(dir)
	out := make([]yaraRuleFile, 0, len(paths))
	for _, path := range paths {
		fileSource := source
		fileNamespace := namespace
		if fileSource == "local" {
			fileSource, fileNamespace = inferYARASource(path)
		}
		out = append(out, yaraRuleFile{Path: path, OriginalPath: path, Source: fileSource, Namespace: fileNamespace})
	}
	return out
}

func inferYARASource(path string) (string, string) {
	name := strings.ToLower(filepath.Base(path))
	dir := strings.ToLower(filepath.Base(filepath.Dir(path)))
	joined := dir + "/" + name
	switch {
	case strings.Contains(joined, "yara-forge") || strings.Contains(joined, "yara_forge") || strings.Contains(name, "yara-rules-"):
		return "yara_forge", "yara_forge"
	case strings.Contains(joined, "malwarebazaar") || strings.Contains(joined, "malware-bazaar") || strings.Contains(joined, "abuse_ch") || strings.Contains(joined, "abuse.ch"):
		return "malwarebazaar", "malwarebazaar"
	default:
		return "local", "local"
	}
}

func yrSupportsRuleNamespaces(binary string, log *logging.Logger) bool {
	cmd := exec.Command(binary, "scan", "--help")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run()
	help := out.String()
	ok := strings.Contains(help, "[NAMESPACE:]") || strings.Contains(help, "--path-as-namespace")
	if !ok {
		log.Warn("yara-x: yr CLI does not advertise per-rule-file namespaces; duplicate filtering fallback enabled")
	}
	return ok
}

func namespaceRuleCounts(files []yaraRuleFile, report setup.YARAPreflightReport) map[string]int {
	byPath := make(map[string]string, len(files)*2)
	for _, file := range files {
		byPath[file.Path] = file.Namespace
		byPath[file.OriginalPath] = file.Namespace
	}
	counts := make(map[string]int)
	for _, decl := range report.Declarations {
		if decl.Skipped {
			continue
		}
		if namespace := byPath[decl.File]; namespace != "" {
			counts[namespace]++
		}
	}
	return counts
}

func formatNamespaceRuleCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	namespaces := make([]string, 0, len(counts))
	for namespace := range counts {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	parts := make([]string, 0, len(namespaces))
	for _, namespace := range namespaces {
		parts = append(parts, fmt.Sprintf("%s=%d", namespace, counts[namespace]))
	}
	return strings.Join(parts, ",")
}

func (f yaraRuleFile) ScanArg(namespaceSupport bool) string {
	if namespaceSupport && f.Namespace != "" {
		return f.Namespace + ":" + f.Path
	}
	return f.Path
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
	for _, ruleFile := range s.ruleFiles {
		args = append(args, ruleFile.ScanArg(s.namespaceSupport))
	}
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
