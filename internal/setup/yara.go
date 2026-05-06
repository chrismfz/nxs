// Package setup handles optional dependency installation (yr binary, YARA Forge rules).
// All downloads use stdlib net/http; no external deps.
package setup

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	yaraxReleasesAPI = "https://api.github.com/repos/VirusTotal/yara-x/releases/latest"
	yaraxBinaryName  = "yr"

	// YARA Forge publishes a pre-built core ruleset bundle.
	yaraForgeBaseURL  = "https://github.com/YARAHQ/yara-forge/releases/latest/download"
	yaraForgePackages = "yara-forge-rules-core.zip"
)


var httpClient = &http.Client{Timeout: 120 * time.Second}

// InstallYARAX downloads the latest yr binary for the current OS/arch
// and writes it to destPath (e.g. /usr/local/bin/yr).
// Returns the installed path on success.
func InstallYARAX(destPath string, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}

	progress("Fetching yara-x latest release info...")
	asset, downloadURL, err := findYARAXAsset()
	if err != nil {
		return fmt.Errorf("yara-x release lookup: %w", err)
	}
	progress(fmt.Sprintf("Downloading %s...", asset))

	tmpFile, err := os.CreateTemp("", "yr-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if err := downloadTo(downloadURL, tmpFile); err != nil {
		tmpFile.Close()
		return fmt.Errorf("download yr: %w", err)
	}
	tmpFile.Close()

	// Asset may be a .tar.gz or .zip containing the yr binary.
	progress("Extracting yr binary...")
	extracted, err := extractBinary(tmpFile.Name(), yaraxBinaryName, asset)
	if err != nil {
		return fmt.Errorf("extract yr: %w", err)
	}
	defer os.Remove(extracted)

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	progress(fmt.Sprintf("Installing yr → %s", destPath))
	return installFile(extracted, destPath, 0755)
}

// InstallYARAForge downloads the YARA Forge core rules bundle and extracts
// all .yar files into rulesDir.
func InstallYARAForge(rulesDir string, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}

	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return err
	}

	url := yaraForgeBaseURL + "/" + yaraForgePackages
	progress(fmt.Sprintf("Downloading YARA Forge core rules from %s...", url))

	tmpFile, err := os.CreateTemp("", "yara-forge-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if err := downloadTo(url, tmpFile); err != nil {
		tmpFile.Close()
		return fmt.Errorf("download yara-forge: %w", err)
	}
	tmpFile.Close()

	progress(fmt.Sprintf("Extracting .yar rules → %s...", rulesDir))
	n, err := extractYARAForgeZip(tmpFile.Name(), rulesDir)
	if err != nil {
		return fmt.Errorf("extract yara-forge: %w", err)
	}
	progress(fmt.Sprintf("Installed %d YARA rule files.", n))
	return nil
}

// ─── GitHub release asset resolution ─────────────────────────────────────────

type ghRelease struct {
	Assets []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func findYARAXAsset() (name, url string, err error) {
	goos := runtime.GOOS     // "linux", "darwin", "windows"
	goarch := runtime.GOARCH // "amd64", "arm64"

	// yara-x release asset names follow the pattern:
	//   yara-x-v1.x.x-x86_64-unknown-linux-gnu.gz
	//   yara-x-v1.x.x-aarch64-unknown-linux-gnu.gz
	//   yara-x-v1.x.x-x86_64-apple-darwin.gz
	//   yara-x-v1.x.x-x86_64-pc-windows-msvc.zip
	archMap := map[string]string{
		"amd64": "x86_64",
		"arm64": "aarch64",
		"386":   "i686",
	}
	osMap := map[string]string{
		"linux":   "unknown-linux-gnu",
		"darwin":  "apple-darwin",
		"windows": "pc-windows-msvc",
	}

	rustArch, ok := archMap[goarch]
	if !ok {
		return "", "", fmt.Errorf("unsupported arch: %s", goarch)
	}
	rustOS, ok := osMap[goos]
	if !ok {
		return "", "", fmt.Errorf("unsupported OS: %s", goos)
	}
	target := rustArch + "-" + rustOS

	req, _ := http.NewRequest("GET", yaraxReleasesAPI, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "nxs-setup/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", err
	}

	for _, a := range rel.Assets {
		if !strings.Contains(a.Name, target) {
			continue
		}
		ext := a.Name
		if strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".zip") || strings.HasSuffix(ext, ".gz") {
			return a.Name, a.BrowserDownloadURL, nil
		}
	}
	return "", "", fmt.Errorf("no yara-x asset found for %s/%s (target=%s)", goos, goarch, target)
}

// ─── Download helper ──────────────────────────────────────────────────────────

func downloadTo(url string, dst *os.File) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}
	_, err = io.Copy(dst, resp.Body)
	return err
}

// ─── Archive extraction ───────────────────────────────────────────────────────

// extractBinary finds `binaryName` inside a .tar.gz, .zip, or plain .gz archive
// and writes it to a temp file, returning the temp file path.
func extractBinary(archivePath, binaryName, assetName string) (string, error) {
	switch {
	case strings.HasSuffix(assetName, ".zip"):
		return extractBinaryFromZip(archivePath, binaryName)
	case strings.HasSuffix(assetName, ".tar.gz"):
		return extractBinaryFromTarGz(archivePath, binaryName)
	default:
		// plain .gz — the compressed stream is the binary itself
		return extractBinaryFromGz(archivePath, binaryName)
	}
}

func extractBinaryFromTarGz(archivePath, binaryName string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		base := filepath.Base(hdr.Name)
		if base == binaryName || base == binaryName+".exe" {
			return writeTmp(tr, binaryName)
		}
	}
	return "", fmt.Errorf("%q not found in archive", binaryName)
}

func extractBinaryFromGz(archivePath, binaryName string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	return writeTmp(gz, binaryName)
}

func extractBinaryFromZip(archivePath, binaryName string) (string, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer zr.Close()

	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if base == binaryName || base == binaryName+".exe" {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			defer rc.Close()
			return writeTmp(rc, binaryName)
		}
	}
	return "", fmt.Errorf("%q not found in zip", binaryName)
}

func writeTmp(r io.Reader, name string) (string, error) {
	tmp, err := os.CreateTemp("", name+"-*")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()
	return tmp.Name(), nil
}

// extractYARAForgeZip extracts all .yar files from the YARA Forge zip into dir.
func extractYARAForgeZip(zipPath, dir string) (int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, err
	}
	defer zr.Close()

	count := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".yar") {
			continue
		}

		destPath := filepath.Join(dir, filepath.Base(f.Name))
		// Prevent zip-slip
		if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(dir)+string(os.PathSeparator)) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return count, err
		}
		if err := writeFileAtomic(destPath, rc, 0644); err != nil {
			rc.Close()
			return count, err
		}
		rc.Close()
		count++
	}
	return count, nil
}

// ─── File install helpers ─────────────────────────────────────────────────────

func installFile(src, dst string, mode os.FileMode) error {
	return writeFileAtomic(dst, mustOpen(src), mode)
}

func mustOpen(path string) *os.File {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	return f
}

func writeFileAtomic(dst string, r io.Reader, mode os.FileMode) error {
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
