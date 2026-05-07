package setup

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// LookupYR returns the resolved absolute path of the yr binary, or an error.
func LookupYR(nameOrPath string) (string, error) {
	if nameOrPath == "" {
		nameOrPath = "yr"
	}
	if strings.HasPrefix(nameOrPath, "/") {
		if _, err := os.Stat(nameOrPath); err != nil {
			return "", err
		}
		return nameOrPath, nil
	}
	return exec.LookPath(nameOrPath)
}

// YARXVersion runs `yr --version` and returns the trimmed version string.
// yr (yara-x) writes its version to stderr, so we capture both streams.
func YARXVersion(path string) (string, error) {
	var out, errBuf bytes.Buffer
	cmd := exec.Command(path, "--version")
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	_ = cmd.Run() // exit code may be non-zero; check output instead
	if s := strings.TrimSpace(out.String()); s != "" {
		return s, nil
	}
	if s := strings.TrimSpace(errBuf.String()); s != "" {
		return s, nil
	}
	return "unknown", nil
}

// CountRuleFiles returns the number of .yar/.yara files in dir.
func CountRuleFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && isYARAPath(name) {
			n++
		}
	}
	return n, nil
}

// CountRules counts individual YARA rule declarations across all .yar/.yara
// files in dir.
func CountRules(dir string) (int, error) {
	report, err := PreflightYARRules(CollectYARFiles(dir))
	if err != nil {
		return 0, err
	}
	return report.TotalRules, nil
}

func countRulesInFile(path string) (int, error) {
	decls, err := ParseYARRuleDeclarations(path)
	if err != nil {
		return 0, err
	}
	return len(decls), nil
}

// CountSigFiles returns the number of files in dir matching any of the given extensions.
func CountSigFiles(dir string, exts ...string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		for _, ext := range exts {
			if strings.HasSuffix(name, ext) {
				n++
				break
			}
		}
	}
	return n, nil
}

// YARRuleDeclaration describes one rule declaration found in a .yar/.yara file.
// Namespace is the effective namespace used when checking for duplicates. The
// current yr backend loads all collected files into one implicit namespace.
type YARRuleDeclaration struct {
	File      string
	Name      string
	Namespace string
	Line      int
	Offset    int
	EndOffset int
	Private   bool
	Global    bool
	Skipped   bool
}

// YARADuplicateRule describes a rule skipped because an earlier declaration
// with the same effective namespace and name was already kept.
type YARADuplicateRule struct {
	File         string
	Name         string
	Namespace    string
	Line         int
	OriginalFile string
	OriginalLine int
}

// YARAParseFailure describes a .yar/.yara file that the lightweight preflight
// parser could not read or slice safely.
type YARAParseFailure struct {
	File string
	Err  string
}

// YARAPreflightReport summarizes the YARA rules that will be active after
// duplicate declarations are skipped.
type YARAPreflightReport struct {
	Files            int
	TotalRules       int
	ActiveRules      int
	DuplicateSkipped int
	ParseFailed      int
	Declarations     []YARRuleDeclaration
	Duplicates       []YARADuplicateRule
	ParseFailures    []YARAParseFailure
}

const yaraGlobalNamespace = "global"

var yaraRuleDeclRE = regexp.MustCompile(`\b(?:(?:private|global)\s+){0,2}rule\s+([A-Za-z_][A-Za-z0-9_]*)\b`)

// CollectYARFiles returns the paths of all .yar/.yara files directly in dir.
func CollectYARFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && isYARAPath(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// PreflightYARRules scans files in order, keeping the first declaration for a
// rule name in each effective namespace and marking later declarations skipped.
func PreflightYARRules(files []string) (YARAPreflightReport, error) {
	report := YARAPreflightReport{Files: len(files)}
	seen := make(map[string]YARRuleDeclaration)
	for _, file := range files {
		decls, err := ParseYARRuleDeclarations(file)
		if err != nil {
			report.ParseFailures = append(report.ParseFailures, YARAParseFailure{File: file, Err: err.Error()})
			continue
		}
		for _, decl := range decls {
			report.TotalRules++
			key := decl.Namespace + "\x00" + decl.Name
			if first, ok := seen[key]; ok {
				decl.Skipped = true
				report.Duplicates = append(report.Duplicates, YARADuplicateRule{
					File:         decl.File,
					Name:         decl.Name,
					Namespace:    decl.Namespace,
					Line:         decl.Line,
					OriginalFile: first.File,
					OriginalLine: first.Line,
				})
			} else {
				seen[key] = decl
				report.ActiveRules++
			}
			report.Declarations = append(report.Declarations, decl)
		}
	}
	report.DuplicateSkipped = len(report.Duplicates)
	report.ParseFailed = len(report.ParseFailures)
	return report, nil
}

// ParseYARRuleDeclarations extracts standard YARA rule declarations from path.
// It ignores comments and quoted strings before applying the declaration regex.
func ParseYARRuleDeclarations(path string) ([]YARRuleDeclaration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sanitized := stripYARACommentsAndStrings(data)
	matches := yaraRuleDeclRE.FindAllSubmatchIndex(sanitized, -1)
	decls := make([]YARRuleDeclaration, 0, len(matches))
	for _, m := range matches {
		start := m[0]
		if !isTopLevelYARADecl(sanitized, start) {
			continue
		}
		nameStart, nameEnd := m[2], m[3]
		prefix := string(sanitized[start:nameStart])
		end := findYARRuleEnd(sanitized, start)
		if end == -1 {
			return nil, fmt.Errorf("rule %q has no complete rule block", string(sanitized[nameStart:nameEnd]))
		}
		decls = append(decls, YARRuleDeclaration{
			File:      path,
			Name:      string(sanitized[nameStart:nameEnd]),
			Namespace: yaraGlobalNamespace,
			Line:      bytes.Count(sanitized[:start], []byte("\n")) + 1,
			Offset:    start,
			EndOffset: end,
			Private:   strings.Contains(prefix, "private"),
			Global:    strings.Contains(prefix, "global"),
		})
	}
	return decls, nil
}

// FilterYARRuleFile writes src to dst while omitting skipped rule blocks listed
// in declarations. Declarations must refer to src and may include declarations
// for other files; those are ignored.
func FilterYARRuleFile(src, dst string, declarations []YARRuleDeclaration) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	type span struct{ start, end int }
	var spans []span
	for _, decl := range declarations {
		if !decl.Skipped || decl.File != src {
			continue
		}
		if decl.Offset < 0 || decl.EndOffset <= decl.Offset || decl.EndOffset > len(data) {
			continue
		}
		spans = append(spans, span{start: decl.Offset, end: decl.EndOffset})
	}
	if len(spans) == 0 {
		return os.WriteFile(dst, data, 0644)
	}
	var out bytes.Buffer
	pos := 0
	for _, sp := range spans {
		if sp.start < pos {
			continue
		}
		out.Write(data[pos:sp.start])
		out.WriteString("\n/* nxs preflight: skipped duplicate YARA rule */\n")
		pos = sp.end
	}
	out.Write(data[pos:])
	return os.WriteFile(dst, out.Bytes(), 0644)
}

func isTopLevelYARADecl(sanitized []byte, offset int) bool {
	depth := 0
	for i := 0; i < offset && i < len(sanitized); i++ {
		switch sanitized[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth == 0
}

func findYARRuleEnd(sanitized []byte, declOffset int) int {
	open := bytes.IndexByte(sanitized[declOffset:], '{')
	if open == -1 {
		return -1
	}
	pos := declOffset + open
	depth := 0
	for i := pos; i < len(sanitized); i++ {
		switch sanitized[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

func stripYARACommentsAndStrings(in []byte) []byte {
	out := append([]byte(nil), in...)
	const (
		normal = iota
		lineComment
		blockComment
		dqString
	)
	state := normal
	for i := 0; i < len(out); i++ {
		c := out[i]
		switch state {
		case normal:
			if c == '/' && i+1 < len(out) && out[i+1] == '/' {
				out[i], out[i+1] = ' ', ' '
				i++
				state = lineComment
			} else if c == '/' && i+1 < len(out) && out[i+1] == '*' {
				out[i], out[i+1] = ' ', ' '
				i++
				state = blockComment
			} else if c == '"' {
				out[i] = ' '
				state = dqString
			}
		case lineComment:
			if c == '\n' {
				state = normal
			} else {
				out[i] = ' '
			}
		case blockComment:
			if c == '*' && i+1 < len(out) && out[i+1] == '/' {
				out[i], out[i+1] = ' ', ' '
				i++
				state = normal
			} else if c != '\n' {
				out[i] = ' '
			}
		case dqString:
			if c == '\\' && i+1 < len(out) {
				out[i], out[i+1] = ' ', ' '
				i++
			} else if c == '"' {
				out[i] = ' '
				state = normal
			} else if c != '\n' {
				out[i] = ' '
			}
		}
	}
	return out
}

func isYARAPath(name string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, ".yar") || strings.HasSuffix(name, ".yara")
}

// execLookPath is an internal alias used by yara.go.
func execLookPath(name string) (string, error) { return exec.LookPath(name) }

// execOutput runs cmd with args and returns stdout.
func execOutput(cmd string, args ...string) (string, error) {
	var buf bytes.Buffer
	c := exec.Command(cmd, args...)
	c.Stdout = &buf
	if err := c.Run(); err != nil {
		return "", err
	}
	return buf.String(), nil
}
