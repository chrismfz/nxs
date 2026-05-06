package setup

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
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
		if !e.IsDir() && (strings.HasSuffix(name, ".yar") || strings.HasSuffix(name, ".yara")) {
			n++
		}
	}
	return n, nil
}

// CountRules counts individual YARA rule declarations across all .yar/.yara
// files in dir by scanning for lines that start with "rule ".
func CountRules(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yar") && !strings.HasSuffix(name, ".yara")) {
			continue
		}
		n, err := countRulesInFile(dir + "/" + name)
		if err == nil {
			total += n
		}
	}
	return total, nil
}

func countRulesInFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// Match "rule Name" and "private rule Name" declarations.
		if strings.HasPrefix(line, "rule ") || strings.HasPrefix(line, "private rule ") {
			n++
		}
	}
	return n, sc.Err()
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
