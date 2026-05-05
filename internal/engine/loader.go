package engine

import (
	"bufio"
	"crypto/md5"
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
	byMD5   map[string]HashEntry
	bySHA256 map[string]HashEntry
}

func LoadHashDB(path string) (*HashIndex, error) {
	idx := &HashIndex{
		byMD5:    make(map[string]HashEntry),
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
		switch e.Algorithm {
		case "md5":
			idx.byMD5[e.Hash] = e
		case "sha256":
			idx.bySHA256[e.Hash] = e
		}
	}
	return idx, nil
}

func (idx *HashIndex) Lookup(hash string) (HashEntry, bool) {
	h := strings.ToLower(hash)
	if e, ok := idx.byMD5[h]; ok {
		return e, true
	}
	if e, ok := idx.bySHA256[h]; ok {
		return e, true
	}
	return HashEntry{}, false
}

func (idx *HashIndex) Len() int {
	return len(idx.byMD5) + len(idx.bySHA256)
}

// HashFile computes MD5 and SHA256 of a file.
func HashFile(path string) (md5sum, sha256sum string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA := sha256.New()
	if _, err = io.Copy(io.MultiWriter(hMD5, hSHA), f); err != nil {
		return "", "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hMD5.Sum(nil)), hex.EncodeToString(hSHA.Sum(nil)), nil
}
