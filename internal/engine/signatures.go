package engine

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/ahocorasick"
)

type Signature struct {
	ID       string
	Pattern  []byte
	Severity string
	Kind     string
	Label    string
}

// LoadSigDir reads *.sig files from dir.
// Each non-comment line: id:severity:kind:pattern  (pattern is literal string)
func LoadSigDir(dir string) ([]Signature, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var sigs []Signature
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sig") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		more, err := parseSigFile(path)
		if err != nil {
			continue
		}
		sigs = append(sigs, more...)
	}
	return sigs, nil
}

func parseSigFile(path string) ([]Signature, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Signature
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			continue
		}
		out = append(out, Signature{
			ID:       strings.TrimSpace(parts[0]),
			Severity: strings.TrimSpace(parts[1]),
			Kind:     strings.TrimSpace(parts[2]),
			Pattern:  []byte(strings.TrimSpace(parts[3])),
		})
	}
	return out, sc.Err()
}

type ACMatcher struct {
	m    *ahocorasick.Matcher
	sigs []Signature
}

func BuildACMatcher(sigs []Signature) *ACMatcher {
	if len(sigs) == 0 {
		return &ACMatcher{sigs: sigs}
	}
	patterns := make([]string, len(sigs))
	for i, s := range sigs {
		patterns[i] = string(s.Pattern)
	}
	return &ACMatcher{
		m:    ahocorasick.NewStringMatcher(patterns),
		sigs: sigs,
	}
}

// Match returns the unique indices of matched signatures and the approximate
// byte offset of each first match.
func (ac *ACMatcher) Match(data []byte) []int {
	if ac.m == nil || len(data) == 0 {
		return nil
	}
	hits := ac.m.Match(data)
	seen := make(map[int]bool)
	var out []int
	for _, h := range hits {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func (ac *ACMatcher) Sig(idx int) Signature {
	return ac.sigs[idx]
}
