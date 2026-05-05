package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/logging"
)

type QuarantineEntry struct {
	ID          string    `json:"id"`
	OrigPath    string    `json:"orig_path"`
	QuarPath    string    `json:"quar_path"`
	FindingID   string    `json:"finding_id"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	Mode        string    `json:"mode"`
	OrigMode    os.FileMode `json:"orig_mode"`
	OrigUID     int       `json:"orig_uid"`
	OrigGID     int       `json:"orig_gid"`
	Size        int64     `json:"size"`
}

type Quarantine struct {
	cfg *config.Config
	log *logging.Logger
}

func NewQuarantine(cfg *config.Config, log *logging.Logger) (*Quarantine, error) {
	if err := os.MkdirAll(cfg.Quarantine.Dir, 0700); err != nil {
		return nil, fmt.Errorf("create quarantine dir: %w", err)
	}
	return &Quarantine{cfg: cfg, log: log}, nil
}

func (q *Quarantine) Quarantine(path string, f *events.Finding) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	id := quarantineID(path)
	safe := safeName(path)
	ts := time.Now().UTC()
	qpath := filepath.Join(q.cfg.Quarantine.Dir, fmt.Sprintf("%s_%s", ts.Format("20060102T150405"), safe))

	meta := QuarantineEntry{
		ID:            id,
		OrigPath:      path,
		QuarPath:      qpath,
		FindingID:     f.ID,
		QuarantinedAt: ts,
		Mode:          q.cfg.Quarantine.Mode,
		OrigMode:      info.Mode(),
		Size:          info.Size(),
	}

	switch q.cfg.Quarantine.Mode {
	case "move":
		if err := os.Rename(path, qpath); err != nil {
			return err
		}
	case "copy":
		if err := copyFile(path, qpath); err != nil {
			return err
		}
	default: // chmod (safest for shared hosting)
		if err := os.Chmod(path, 0000); err != nil {
			return err
		}
		qpath = path // no separate quarantine path for chmod mode
		meta.QuarPath = path
	}

	if err := writeMeta(qpath+".nxsmeta.json", meta); err != nil {
		q.log.Warn("failed to write quarantine meta", "path", path, "err", err)
	}

	f.Action = "quarantine_" + q.cfg.Quarantine.Mode
	f.ActionResult = "ok"
	return nil
}

func (q *Quarantine) List() ([]QuarantineEntry, error) {
	entries, err := os.ReadDir(q.cfg.Quarantine.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []QuarantineEntry
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".nxsmeta.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(q.cfg.Quarantine.Dir, e.Name()))
		if err != nil {
			continue
		}
		var qe QuarantineEntry
		if err := json.Unmarshal(data, &qe); err != nil {
			continue
		}
		out = append(out, qe)
	}
	return out, nil
}

func quarantineID(path string) string {
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:8])
}

func safeName(path string) string {
	s := strings.ReplaceAll(path, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 80 {
		s = s[len(s)-80:]
	}
	return s
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func writeMeta(path string, meta QuarantineEntry) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
