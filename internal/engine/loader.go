package engine

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

type HashEntry struct {
	Algorithm string
	Hash      string
	Severity  string
	Kind      string
	Label     string
}

type HashIndex struct {
	byMD5    map[string]HashEntry
	bySHA1   map[string]HashEntry
	bySHA256 map[string]HashEntry
}

func LoadHashDB(path string) (*HashIndex, error) {
	idx := &HashIndex{
		byMD5:    make(map[string]HashEntry),
		bySHA1:   make(map[string]HashEntry),
		bySHA256: make(map[string]HashEntry),
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return idx, nil
		}
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReader(f))
	r.Comment = '#'
	header := true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if header {
			header = false
			continue
		}
		if len(rec) < 5 {
			continue
		}
		e := HashEntry{
			Algorithm: strings.TrimSpace(rec[0]),
			Hash:      strings.ToLower(strings.TrimSpace(rec[1])),
			Severity:  strings.TrimSpace(rec[2]),
			Kind:      strings.TrimSpace(rec[3]),
			Label:     strings.TrimSpace(rec[4]),
		}
		idx.insert(e)
	}
	return idx, nil
}

// LoadClamAVHDB loads a ClamAV .hdb (MD5) or .hsb (SHA1/SHA256) hash database.
// Format: hash:filesize:MalwareName  (filesize may be * for any size)
func LoadClamAVHDB(path string, idx *HashIndex) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		hash := strings.ToLower(strings.TrimSpace(parts[0]))
		name := strings.TrimSpace(parts[2])
		if hash == "" || name == "" {
			continue
		}

		algo := clamHashAlgo(hash)
		if algo == "" {
			continue
		}

		e := HashEntry{
			Algorithm: algo,
			Hash:      hash,
			Severity:  "high",
			Kind:      "malware",
			Label:     name,
		}
		idx.insert(e)
		n++
	}
	return n, sc.Err()
}

// clamHashAlgo returns the algorithm name for a ClamAV hash by its hex length.
// MD5=32, SHA1=40, SHA256=64. Returns "" for unrecognised lengths.
func clamHashAlgo(h string) string {
	switch len(h) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	}
	return ""
}

func (idx *HashIndex) insert(e HashEntry) {
	switch e.Algorithm {
	case "md5":
		idx.byMD5[e.Hash] = e
	case "sha1":
		idx.bySHA1[e.Hash] = e
	case "sha256":
		idx.bySHA256[e.Hash] = e
	}
}

func (idx *HashIndex) Lookup(hash string) (HashEntry, bool) {
	h := strings.ToLower(hash)
	if e, ok := idx.byMD5[h]; ok {
		return e, true
	}
	if e, ok := idx.bySHA1[h]; ok {
		return e, true
	}
	if e, ok := idx.bySHA256[h]; ok {
		return e, true
	}
	return HashEntry{}, false
}

func (idx *HashIndex) Len() int {
	return len(idx.byMD5) + len(idx.bySHA1) + len(idx.bySHA256)
}

// HashFile computes MD5, SHA1, and SHA256 of a file.
func HashFile(path string) (md5sum, sha1sum, sha256sum string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()
	if _, err = io.Copy(io.MultiWriter(hMD5, hSHA1, hSHA256), f); err != nil {
		return "", "", "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hMD5.Sum(nil)),
		hex.EncodeToString(hSHA1.Sum(nil)),
		hex.EncodeToString(hSHA256.Sum(nil)),
		nil
}
