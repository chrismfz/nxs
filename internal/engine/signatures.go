package engine

import (
	"bufio"
	"encoding/hex"
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

// LoadNDB loads a ClamAV .ndb file and returns signatures for exact-match
// entries (no wildcards). Entries with ??, (, [, or { are skipped — they
// require regex matching which is not yet implemented.
//
// NDB format: MalwareName:TargetType:Offset:HexSignature[:MinFL:MaxFL]
// TargetType 0 = any file; others are PE/OLE/HTML/etc. We load type 0 and
// type 7 (ASCII text) since those apply to web files on hosting servers.
//
// Returns (loaded, skipped) counts.
func LoadNDB(path string) (sigs []Signature, loaded, skipped int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 5)
		if len(parts) < 4 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		targetType := strings.TrimSpace(parts[1])
		hexSig := strings.TrimSpace(parts[3])

		// Only load signatures that apply to any file or ASCII text.
		if targetType != "0" && targetType != "7" {
			skipped++
			continue
		}

		// Skip entries with wildcard/alternation syntax — not yet supported.
		if strings.ContainsAny(hexSig, "?({[") {
			skipped++
			continue
		}

		b, decErr := hex.DecodeString(hexSig)
		if decErr != nil || len(b) < 4 {
			skipped++
			continue
		}

		sigs = append(sigs, Signature{
			ID:       name,
			Pattern:  b,
			Severity: "medium",
			Kind:     "malware",
			Label:    name,
		})
		loaded++
	}
	return sigs, loaded, skipped, sc.Err()
}
