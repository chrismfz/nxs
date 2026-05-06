package setup

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// supportedExts lists extensions the NXS engine can actually load.
// Files with other extensions are downloaded but a note is logged so the
// operator knows they won't be active until support is added.
var supportedExts = map[string]string{
	".yar":  "YARA rules",
	".yara": "YARA rules",
	".hdb":  "ClamAV MD5 hash DB",
	".hsb":  "ClamAV SHA hash DB",
	".ndb":  "ClamAV NDB patterns (exact-match entries loaded)",
	".sig":  "NXS AC patterns",
	".csv":  "NXS hash CSV",
}

// unsupportedExts are downloaded (so they're ready if support is added later)
// but not loaded by the engine.
var unsupportedExts = map[string]string{
	".ldb":  "ClamAV logical sigs (not loaded)",
	".ign2": "ClamAV ignore list (not loaded)",
	".cld":  "ClamAV compiled DB (binary, cannot load)",
	".cvd":  "ClamAV compiled DB (binary, cannot load)",
}

// DownloadDBs downloads all URLs into sigDir, using If-Modified-Since so only
// changed files are fetched. Returns counts of (downloaded, skipped, failed).
func DownloadDBs(urls []string, sigDir string, progress func(string)) (downloaded, skipped, failed int) {
	if err := os.MkdirAll(sigDir, 0750); err != nil {
		progress(fmt.Sprintf("  error: cannot create sig dir: %v", err))
		failed = len(urls)
		return
	}

	for _, rawURL := range urls {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}

		name, err := urlFilename(rawURL)
		if err != nil {
			progress(fmt.Sprintf("  skip  : bad URL %q: %v", rawURL, err))
			failed++
			continue
		}

		ext := strings.ToLower(filepath.Ext(name))
		if desc, ok := unsupportedExts[ext]; ok {
			// Still download — engine will ignore it, but it's there for future use.
			progress(fmt.Sprintf("  note  : %s — %s", name, desc))
		}

		destPath := filepath.Join(sigDir, name)
		ok, err := downloadIfNewer(rawURL, destPath, progress)
		if err != nil {
			progress(fmt.Sprintf("  error : %s: %v", name, err))
			failed++
		} else if ok {
			if desc, ok := supportedExts[ext]; ok {
				progress(fmt.Sprintf("  saved : %s (%s)", name, desc))
			} else {
				progress(fmt.Sprintf("  saved : %s", name))
			}
			downloaded++
		} else {
			progress(fmt.Sprintf("  up-to-date: %s", name))
			skipped++
		}
	}
	return
}

// downloadIfNewer fetches url to destPath, skipping if the server reports
// nothing has changed (304 Not Modified). Returns true if the file was written.
func downloadIfNewer(rawURL, destPath string, progress func(string)) (bool, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "nxs-signatures/1.0")

	// Conditional: only re-download if the server has a newer version.
	if info, err := os.Stat(destPath); err == nil {
		req.Header.Set("If-Modified-Since", info.ModTime().UTC().Format(http.TimeFormat))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
		// fall through
	default:
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Atomic write: tmp → rename
	tmp := destPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return false, err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return false, fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, os.Rename(tmp, destPath)
}

func urlFilename(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	name := filepath.Base(u.Path)
	if name == "" || name == "." || name == "/" {
		return "", fmt.Errorf("cannot derive filename from URL path %q", u.Path)
	}
	// Reject path traversal
	if strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("unsafe filename %q", name)
	}
	return name, nil
}
