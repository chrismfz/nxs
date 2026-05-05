package setup

import (
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

// YARXVersion runs `yr --version` and returns the trimmed output.
func YARXVersion(path string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command(path, "--version")
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return "unknown", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// CountRules returns the number of .yar files in dir.
func CountRules(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yar") {
			n++
		}
	}
	return n, nil
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
