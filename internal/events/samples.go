package events

import (
	"encoding/hex"
	"os"
	"unicode"
)

const sampleWindow = 64

// ExtractSamples reads byte windows around match offsets from a file.
// Returns at most n samples.
func ExtractSamples(path string, offsets []int64, n int) []Sample {
	if len(offsets) == 0 || n <= 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[int64]bool)
	var out []Sample
	for _, off := range offsets {
		if seen[off] || len(out) >= n {
			break
		}
		seen[off] = true

		start := off - sampleWindow/2
		if start < 0 {
			start = 0
		}
		buf := make([]byte, sampleWindow)
		nr, _ := f.ReadAt(buf, start)
		if nr == 0 {
			continue
		}
		buf = buf[:nr]
		out = append(out, Sample{
			Type:    "bytes",
			Path:    path,
			Content: toASCII(buf),
			Hash:    hex.EncodeToString(buf),
		})
	}
	return out
}

func toASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if unicode.IsPrint(rune(c)) && c < 128 {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}
