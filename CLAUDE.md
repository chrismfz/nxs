# NXS — Claude Code Agent Guide

## Project overview

NXS is a host security scanner for shared Linux/cPanel hosting servers.  
Sister project to [CFM](https://github.com/chrismfz/cfm) (firewall/WAF).  
Static binary (`CGO_ENABLED=0`, `netgo osusergo`), no SQLite, no CGO deps.

## Development branch

All work goes on: `claude/plan-nxs-upload-dssi7`

## Build

```bash
make build        # produces bin/nxs
make deb          # Debian package → build/deb/
make rpm          # RPM → packaging/rpm/RPMS/
make release      # deb + rpm + GitHub release upload
make sync         # rsync packages to repo.nixpal.com
```

## External dependencies (Go)

- `github.com/cloudflare/ahocorasick` — Aho-Corasick pattern matching (Tier 2)
- stdlib only for everything else (config, CLI, JSONL, locking, HTTP)

## Runtime dependencies (host, optional)

- `yr` (yara-x) — Tier 3 YARA scanning; `nxs signatures setup` auto-installs it
- YARA Forge rules — `nxs signatures update` auto-downloads them

## Package layout

```
cmd/nxs/           — binary entry point, CLI dispatch
internal/
  config/          — INI config loader (stdlib bufio, no viper)
  logging/         — slog wrapper (JSON → file + stderr WARN+)
  events/          — Finding struct, JSONL writer, state store
  exclusions/      — path/hash/regex exclusion rules
  maintenance/     — maintenance window scheduler
  engine/          — Tier1 hash, Tier2 AC, Tier3 YARA-X, reload
  scanner/         — pipeline, quarantine, periodic scanner
  filewatch/       — fanotify stub + fallback (build-tag split)
  notify/          — sendmail, SMTP, Slack notifier
  setup/           — yr binary + YARA Forge rules auto-install (nxs signatures setup|update|status)
  integrity/       — stub (post-beta)
  runtime/         — stub (post-beta)
  cfmclient/       — stub (post-beta)
  cleaner/         — stub (post-beta)
  wpintegrity/     — stub (post-beta)
  cmsintegrity/    — stub (post-beta)
  dbscanner/       — stub (post-beta)
configs/           — nxs.conf.example, hashdb.csv, signatures/
packaging/         — RPM spec, Debian control files, systemd unit
docs/roadmaps/     — roadmap-v2.md (feature checklist lives here)
```

## Documentation rules (follow on every commit)

### When you add or complete a feature

1. **Roadmap checklist** (`docs/roadmaps/roadmap-v2.md`):
   - Change `[ ]` → `[x]` for every item the commit completes
   - Add new `[ ]` items for anything deferred

2. **README.md**:
   - If the feature adds or changes a CLI subcommand → update the "CLI overview" table
   - If the feature adds a config key → update the "Configuration" section (or note it in the example)
   - If the feature adds a testing step → add it to "Testing without installing"

3. **`configs/nxs.conf.example`**:
   - Every new `Config` field must have a matching commented line in the example

4. **This file (`CLAUDE.md`)**:
   - Update "Runtime dependencies" if a new optional host tool is added
   - Update "Package layout" if a new internal package is added

### When you fix a bug

- Update any affected README testing step if the fix changes expected output
- No roadmap update needed for pure bug fixes

### Commit message format

```
<scope>: <short imperative description>

Optional longer body explaining why, not what.

https://claude.ai/code/session_01PrFesKxRHuZ5o5nhPFNRCx
```

Scopes: `engine`, `scanner`, `config`, `notify`, `filewatch`, `setup`, `packaging`, `docs`, `cmd`

### After every implementation step

Run the smoke-test from the README "Testing without installing" section and confirm:
- `make build` succeeds with zero warnings
- `./bin/nxs --version` prints version
- `./bin/nxs scan /tmp/nxs-scan` produces expected findings
- No new `go vet` or `go build` errors

## Key design decisions (do not reverse without discussion)

- **No cobra/viper** — stdlib `flag` + manual subcommand dispatch in `main.go`
- **No external INI lib** — stdlib `bufio` line-scanner in `internal/config/`
- **JSONL over SQLite** — CGO_ENABLED=0; JSONL appends are atomic; `jq`-friendly
- **`chmod 0000` default quarantine** — preserves inode/path on shared hosting
- **Atomic writes** — all state files: write `.tmp` → `os.Rename`; never truncate-in-place
- **fanotify build-tag split** — `monitor_linux.go` / `monitor_other.go`; real-time loop deferred post-beta
- **yr subprocess** — yara-x via exec, NDJSON output; avoids CGO (`go-yara` rejected)
- **Graceful degradation** — missing yr, empty hashdb, empty signatures dir → scan continues, YARA tier silently skipped

## Config struct → conf key mapping

When adding a field to `internal/config/config.go`, the INI key is the field name uppercased with underscores. Example: `YARARulesDir` → `YARA_RULES_DIR` in `[engine]`.

## Testing

```bash
# Unit smoke test (no root required)
mkdir -p /tmp/nxs-test/{logs,state,quarantine,sigs}
# See README "Testing without installing" for full setup
make build
./bin/nxs -c /tmp/nxs-test/nxs.conf scan /tmp/nxs-scan
./bin/nxs -c /tmp/nxs-test/nxs.conf findings --since 1h
```

## Roadmap

See `docs/roadmaps/roadmap-v2.md` — the first-session checklist at the top tracks beta completion.
