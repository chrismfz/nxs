# NXS — iNtegrity eXploit Scanner

Host security scanner for shared Linux/cPanel hosting servers.

**Status:** Pre-beta / active development  
**Sister project:** [CFM](https://github.com/chrismfz/cfm) (firewall/WAF/network enforcement)

---

## What NXS does

```
filesystem malware scanning       — hash + pattern + YARA tiers
real-time fanotify monitoring     — GroupWeb, GroupSystem, GroupRuntime
webshell / dropper detection      — Aho-Corasick signatures
quarantine and surgical cleaning  — preserve originals, allow restore
WordPress / CMS integrity         — official checksum APIs
database infection scanning       — WP posts/options/users/cron
rootkit / post-exploitation       — preload, SUID, cron, systemd, SSH keys
runtime file access visibility    — fanotify observe-only
safe findings workflow            — JSONL log, exclusions, maintenance mode
```

## What NXS is not

NXS is **not** a firewall. It does not manage nftables, WAF rules, or network traffic.  
Those are **CFM** responsibilities.

```
CFM = traffic / WAF / challenge / network enforcement
NXS = filesystem / malware / integrity / rootkit / cleanup
```

---

## Quick start

```bash
# Install (creates /var/lib/nxs, /var/log/nxs, /var/run/nxs automatically)
rpm -i nxs-*.rpm          # RHEL/CentOS/AlmaLinux
dpkg -i nxs-*.deb         # Debian/Ubuntu

# Configure
cp /usr/share/nxs/configs/nxs.conf.example /etc/nxs/nxs.conf
$EDITOR /etc/nxs/nxs.conf

# Start daemon
systemctl enable --now nxs

# Scan now
nxs scan /home
nxs findings --since 1h --severity high
```

---

## Testing without installing

The steps below let you smoke-test the binary against synthetic payloads from the repo root.

**1. Create a local writable environment**

```bash
mkdir -p /tmp/nxs-test/{logs,state,quarantine,sigs}

cat > /tmp/nxs-test/nxs.conf <<'EOF'
[main]
DATA_DIR = /tmp/nxs-test
LOG_DIR  = /tmp/nxs-test/logs
RUN_DIR  = /tmp/nxs-test

[findings]
LOG_PATH   = /tmp/nxs-test/findings.jsonl
STATE_PATH = /tmp/nxs-test/state/findings.json
NOTIFY     = 0

[engine]
ENABLED  = 1
SIG_DIR  = /tmp/nxs-test/sigs
HASH_DB  = /tmp/nxs-test/hashdb.csv

[scanner]
ENABLED          = 1
WATCH_PATHS      = /tmp/nxs-scan
PERIODIC_ENABLED = 0

[quarantine]
DIR  = /tmp/nxs-test/quarantine
MODE = chmod

[notify]
ENABLED = 0

[exclusions]
FILE = /tmp/nxs-test/state/exclusions.json

[maintenance]
STATE_PATH = /tmp/nxs-test/state/maintenance.json
EOF

mkdir -p /tmp/nxs-scan
```

**2. Add an EICAR hash (Tier 1 — hash lookup)**

```bash
cat > /tmp/nxs-test/hashdb.csv <<'EOF'
algorithm,hash,severity,kind,label
md5,44d88612fea8a8f36de82e1278abb02f,critical,malware,eicar-test
EOF

# Real EICAR test file (safe, not real malware)
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > /tmp/nxs-scan/eicar.com
```

**3. Add pattern signatures (Tier 2 — Aho-Corasick)**

```bash
cat > /tmp/nxs-test/sigs/webshells.sig <<'EOF'
ws-eval-b64:high:webshell:eval(base64_decode(
ws-cmd-get:high:webshell:$_GET["cmd"]
ws-cmd-post:high:webshell:$_POST["cmd"]
ws-system-get:high:webshell:system($_GET[
ws-exec-request:high:webshell:exec($_REQUEST[
ws-gzinflate:medium:dropper:gzinflate(str_rot13(
EOF
```

**4. Create synthetic payloads**

```bash
# Webshell — triggers ws-eval-b64 + ws-cmd-get
printf '<?php eval(base64_decode("dGVzdA==")); echo $_GET["cmd"]; ?>' \
  > /tmp/nxs-scan/shell.php

# Dropper — triggers ws-gzinflate
printf '<?php eval(gzinflate(str_rot13(base64_decode("test")))); ?>' \
  > /tmp/nxs-scan/dropper.php

# Clean file — no findings expected
echo "Hello world" > /tmp/nxs-scan/clean.txt
```

**5. Scan**

```bash
make build
./bin/nxs -c /tmp/nxs-test/nxs.conf scan /tmp/nxs-scan
```

Expected output: `eicar.com` → critical, `shell.php` → high (×2), `dropper.php` → medium, `clean.txt` → nothing.

**6. Query findings**

```bash
# Human-readable summary
./bin/nxs -c /tmp/nxs-test/nxs.conf findings --since 1h --severity info

# Raw JSONL
./bin/nxs -c /tmp/nxs-test/nxs.conf findings --json | jq '{path:.Source,kind:.Kind,sev:.Severity}'

# Only high+
./bin/nxs -c /tmp/nxs-test/nxs.conf findings --severity high --json
```

**7. Quarantine check**

```bash
# chmod 0000 quarantine — file stays in place, permissions zeroed
ls -la /tmp/nxs-scan/eicar.com
./bin/nxs -c /tmp/nxs-test/nxs.conf quarantine list
```

**8. Exclusions**

```bash
./bin/nxs -c /tmp/nxs-test/nxs.conf exclusions add path /tmp/nxs-scan/clean.txt
./bin/nxs -c /tmp/nxs-test/nxs.conf exclusions list

# Re-scan — clean.txt suppressed in output
./bin/nxs -c /tmp/nxs-test/nxs.conf scan /tmp/nxs-scan
```

**9. Daemon mode**

```bash
./bin/nxs -c /tmp/nxs-test/nxs.conf daemon &
NXS_PID=$!

# Trigger engine reload (re-reads hashdb + signatures)
kill -HUP $NXS_PID

# Graceful stop
kill -TERM $NXS_PID
```

**10. YARA-X (Tier 3) — auto-setup**

`nxs signatures setup` downloads the `yr` binary from [yara-x releases](https://github.com/VirusTotal/yara-x/releases)
and the [YARA Forge](https://github.com/YARAHQ/yara-forge) core rule bundle in one command.

```bash
# After package install (writes yr to /usr/local/bin, rules to /var/lib/nxs/yara)
sudo nxs signatures setup

# Without root — point config at writable paths
mkdir -p /tmp/nxs-test/yara

cat >> /tmp/nxs-test/nxs.conf <<'EOF'
YARA_ENABLED   = 1
YARA_BINARY    = /usr/local/bin/yr
YARA_RULES_DIR = /tmp/nxs-test/yara
EOF

# Download yr manually if no root:
#   https://github.com/VirusTotal/yara-x/releases → pick yr-*-x86_64-unknown-linux-musl.tar.gz
#   tar xf yr-*.tar.gz && mv yr /tmp/nxs-test/yr
# then set YARA_BINARY = /tmp/nxs-test/yr in the config above.

# Download YARA Forge rules into the local dir
./bin/nxs -c /tmp/nxs-test/nxs.conf signatures update

# Confirm status
./bin/nxs -c /tmp/nxs-test/nxs.conf signatures status
# ── yr (yara-x) ──────────────────────────────
#   binary : /usr/local/bin/yr
#   version: yr 0.x.x
# ── YARA rules ───────────────────────────────
#   dir    : /tmp/nxs-test/yara
#   files  : 312 .yar files

# Scan with all three tiers active
./bin/nxs -c /tmp/nxs-test/nxs.conf scan /tmp/nxs-scan

# Findings from YARA Forge rules show kind=malware, source=yara-x
./bin/nxs -c /tmp/nxs-test/nxs.conf findings --severity high --json | \
  jq 'select(.Source=="yara-x") | {rule:.Evidence.rule, path:.Path, sev:.Severity}'
```

---

## YARA Forge

[YARA Forge](https://github.com/YARAHQ/yara-forge) aggregates curated rules from public threat intelligence repos
(Elastic, Florian Roth, MalwareBazaar, and others) into pre-built packages.

NXS uses the **core** package — high-confidence, low-FP rules suitable for automated scanning.

### Rule packages

| Package | Size | Use case |
|---------|------|----------|
| `core`  | ~300 rules | Default — high confidence, automated scanning |
| `full`  | ~3000+ rules | Manual review — includes research/experimental rules |

`nxs signatures setup|update` always fetches the `core` package.  
To use `full`, download it manually from the YARA Forge releases page and point `YARA_RULES_DIR` at it.

### Updating rules

```bash
# On demand
nxs signatures update

# Weekly cron (root) — keeps rules fresh without manual intervention
echo "0 3 * * 0  root  /usr/bin/nxs signatures update" > /etc/cron.d/nxs-yara
```

### Writing your own rules

Drop any `.yar` file into `YARA_RULES_DIR`. NXS passes the entire directory to `yr scan`, so new files are picked up automatically on the next scan. Reload the engine without restarting the daemon:

```bash
kill -HUP $(pidof nxs)     # triggers SIGHUP → engine reload
```

**Rule metadata NXS reads:**

| Key | Effect |
|-----|--------|
| `severity` | Maps to NXS severity (critical/high/medium/low/info); default: high |
| `threat_level` | Alternative severity key (1–5 or word) |
| `description` | Used as the finding message |
| `desc` | Fallback for `description` |

Example rule compatible with NXS severity mapping:

```yara
rule php_eval_webshell {
    meta:
        description = "PHP webshell using eval+base64"
        severity    = "high"
        author      = "local"
    strings:
        $a = "eval(base64_decode(" ascii
        $b = "eval(gzinflate(" ascii
    condition:
        any of them
}
```

Place it in `YARA_RULES_DIR`, then:

```bash
# Test rule against a single file before deploying
yr scan /tmp/nxs-test/yara /tmp/nxs-scan/shell.php

# Or via nxs (logs finding to findings.jsonl)
./bin/nxs -c /tmp/nxs-test/nxs.conf scan /tmp/nxs-scan/shell.php
./bin/nxs -c /tmp/nxs-test/nxs.conf findings --since 1m --json | jq .
```

### Excluding noisy YARA Forge rules

If a YARA Forge rule produces false positives on a legitimate file:

```bash
# Suppress by path
nxs exclusions add path /home/user/legitimate_script.php

# Or remove the specific .yar file from the rules dir and reload
rm /var/lib/nxs/yara/noisy_rule.yar
kill -HUP $(pidof nxs)
```

---

## CLI overview

```bash
nxs daemon                        # systemd entry point
nxs scan <path>                   # scan file or directory
nxs findings [--since 24h]        # query findings log
nxs quarantine list               # list quarantined files
nxs exclusions list|add|remove    # manage exclusions
nxs maintenance list|add|remove   # manage maintenance windows
nxs signatures status             # show yr binary + YARA rules status
nxs signatures setup              # download yr binary + YARA Forge core rules
nxs signatures update             # re-download YARA Forge core rules
nxs wp scan <wp-root>             # WordPress integrity check
nxs db scan <user>                # database malware scan
nxs integrity scan                # real-time integrity check
```

---

## Repository layout

```
cmd/nxs/          — binary entry point
internal/
  config/         — INI config loader
  logging/        — structured JSON logger
  events/         — Finding struct, JSONL writer, state store
  exclusions/     — path/hash/regex exclusion rules
  maintenance/    — maintenance window scheduler
  engine/         — hash + Aho-Corasick + YARA scan engine
  scanner/        — pipeline, quarantine, periodic scanner
  filewatch/      — fanotify monitor with graceful fallback
  notify/         — sendmail, SMTP, Slack notifier
  integrity/      — real-time integrity detector
  runtime/        — fanotify runtime access monitor
  cfmclient/      — thin HTTP client to call CFM block API
  cleaner/        — surgical PHP injection cleaner
  wpintegrity/    — WordPress core/plugin checksum checker
  cmsintegrity/   — Joomla/Drupal/Magento/OpenCart integrity
  dbscanner/      — WordPress DB malware scanner
configs/          — nxs.conf.example, hashdb.csv, signatures/
packaging/        — RPM spec, Debian control, systemd unit
docs/roadmaps/    — project roadmap
```

---

## Roadmap

See [docs/roadmaps/roadmap-v2.md](docs/roadmaps/roadmap-v2.md) for the full feature roadmap and dependency graph.

---

## License

MIT
