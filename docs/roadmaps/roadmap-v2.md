# NXS — iNtegrity eXploit Scanner Roadmap v2

**Repository:** `github.com/chrismfz/nxs`  
**Status:** Planning / pre-development  
**Relation to CFM:** Sister project. Same author, separate binary, separate scope.

---

## 0. Product boundary

### What NXS is

NXS is a host security scanner for shared Linux/cPanel hosting servers.

It focuses on:

```text
filesystem malware scanning
real-time fanotify monitoring
webshell/dropper detection
quarantine and surgical cleaning
WordPress/CMS integrity
database infection scanning
rootkit/post-exploitation indicators
runtime file access/exec visibility
safe notifications and findings workflow
```

### What NXS is not

NXS is **not** a firewall.

It does not:

```text
manage nftables
intercept HTTP traffic
run a WAF challenge
DNAT cPanel/WHM ports
rate-limit network traffic
handle login-failure blocking directly
```

Those remain **CFM** responsibilities.

```text
CFM = traffic / WAF / firewall / challenge / network enforcement
NXS = filesystem / malware / integrity / rootkit / cleanup
```

---

## 1. Relationship with CFM

NXS and CFM are independent.

```text
nxs only:
  scans filesystem
  quarantines/cleans files
  sends notifications
  logs findings
  does not block network IPs

cfm only:
  firewall/WAF/challenge/login/network protection

nxs + cfm:
  NXS finds malware or post-exploitation artifact
  NXS optionally calls CFM API to block attacker IP
  CFM performs nftables block/enrichment/notification
```

### NXS → CFM API seam

```ini
[cfm]
ENABLED   = 1
API_URL   = https://127.0.0.1:6061
API_TOKEN = <token from cfm.conf>
BLOCK_TTL = 24h
BLOCK_ON  = webshell,dropper,rootkit_artifact,binary_tampered,runtime_exec
```

No CFM internals should be imported by NXS.

NXS uses a thin HTTP client only:

```text
internal/cfmclient/
  client.go
  block.go
  health.go
```

---

## 2. Repository structure

```text
nxs/
  cmd/nxs/
    main.go

  internal/
    config/
    logging/

    events/
      event.go
      severity.go
      jsonl.go
      state.go
      samples.go
      diff.go
      redact.go

    exclusions/
      exclusions.go
      match.go
      store.go

    maintenance/
      maintenance.go

    notify/
      notify.go
      sendmail.go
      smtp.go
      slack.go
      routes.go
      dedupe.go

    cfmclient/
      client.go
      block.go
      health.go

    engine/
      builder.go
      loader.go
      signatures.go
      reload.go
      stats.go

    clam/
      clam.go

    filewatch/
      watcher.go
      monitor.go
      monitor_linux.go
      monitor_other.go
      filter.go

    scanner/
      pipeline.go
      filter.go
      dedup.go
      periodic.go
      quarantine.go
      action.go
      scan.go

    cleaner/
      cleaner.go
      strategies.go
      entropy.go
      backup.go
      restore.go

    wpintegrity/
      detect.go
      fetch.go
      check.go
      cache.go
      plugins.go

    cmsintegrity/
      joomla.go
      drupal.go
      magento.go
      opencart.go

    dbscanner/
      discover.go
      wp.go
      wp_clean.go
      backup.go
      result.go

    integrity/
      findings.go
      signatures.go
      baseline.go
      detector.go
      proccheck.go
      filecheck.go
      startscan.go
      rpmcheck.go
      services.go
      cron.go
      ssh.go
      systemd.go
      suid.go
      preload.go

    runtime/
      events.go
      fanotify_linux.go
      fanotify_other.go
      classify.go
      proc.go
      hash.go
      policy.go

  configs/
    nxs.conf
    nxs.conf.example

  packaging/
    rpm/
    debian/

  docs/
    roadmaps/

  Makefile
  go.mod
  go.sum
```

---

# Feature 0 — Finding/Event Framework

This should come **before** the scanner engine.

Every NXS subsystem should emit the same structured finding format:

```text
native malware engine
yara rules integration
fanotify monitor
scanner pipeline
quarantine
cleaner
WordPress/CMS integrity
database scanner
real-time integrity detector
runtime access monitor
notifier
CFM block client
```

## Persistent files

```text
/var/log/nxs/findings.log
/var/lib/nxs/state/findings.json
/var/lib/nxs/state/exclusions.json
/var/lib/nxs/state/maintenance.json
```

`findings.log` is JSONL.

## Finding model

```go
type Finding struct {
    ID        string    `json:"id"`
    TS        time.Time `json:"ts"`
    Hostname  string    `json:"hostname"`

    Component string `json:"component"`
    Source    string `json:"source"`
    Severity  string `json:"severity"`
    Kind      string `json:"kind"`

    Message string `json:"message"`

    Path  string `json:"path,omitempty"`
    PID   int    `json:"pid,omitempty"`
    PPID  int    `json:"ppid,omitempty"`
    UID   int    `json:"uid,omitempty"`
    GID   int    `json:"gid,omitempty"`
    User  string `json:"user,omitempty"`
    Group string `json:"group,omitempty"`

    Evidence map[string]any `json:"evidence,omitempty"`
    Samples  []Sample       `json:"samples,omitempty"`
    Diff     *Diff          `json:"diff,omitempty"`

    Action       string `json:"action,omitempty"`
    ActionResult string `json:"action_result,omitempty"`

    CFMBlockAttempted bool   `json:"cfm_block_attempted,omitempty"`
    CFMBlockResult    string `json:"cfm_block_result,omitempty"`

    ExcludeHint string `json:"exclude_hint,omitempty"`

    FirstSeen time.Time `json:"first_seen,omitempty"`
    LastSeen  time.Time `json:"last_seen,omitempty"`
    Count     int       `json:"count,omitempty"`

    Suppressed            bool      `json:"suppressed,omitempty"`
    SuppressReason        string    `json:"suppress_reason,omitempty"`
    MaintenanceSuppressed bool      `json:"maintenance_suppressed,omitempty"`
    NotifyEligible        bool      `json:"notify_eligible,omitempty"`
    NotifiedAt            time.Time `json:"notified_at,omitempty"`
}
```

## Samples and diff

```go
type Sample struct {
    Type    string `json:"type"`
    Path    string `json:"path,omitempty"`
    LineNo  int    `json:"line_no,omitempty"`
    Content string `json:"content,omitempty"`
    Hash    string `json:"hash,omitempty"`
}

type Diff struct {
    Added   []Sample `json:"added,omitempty"`
    Removed []Sample `json:"removed,omitempty"`
    Changed []Sample `json:"changed,omitempty"`
}
```

## Safety rules

Never log:

```text
private keys
full authorized_keys lines
full binary file content
database passwords
API tokens
bearer tokens
secret values
```

Redact:

```text
password=
passwd=
token=
secret=
apikey=
api_key=
Authorization:
Bearer <token>
access_token=
refresh_token=
DB_PASSWORD=
MYSQL_PWD=
AWS_SECRET_ACCESS_KEY=
```

Defang URLs:

```text
http://  -> hxxp://
https:// -> hxxps://
```

---

# Feature 0.1 — Exclusions

NXS needs exclusions from day one.

```json
{
  "id": "exc_abc123",
  "created_at": "2026-05-04T18:00:00+03:00",
  "component": "integrity",
  "kind": "PROCESS_EXE_DELETED",
  "field": "exe",
  "regex": "/usr/sbin/nginx \\(deleted\\)",
  "reason": "nginx package upgrade",
  "enabled": true
}
```

Supported fields:

```text
path
sha256
md5
user
uid
gid
pid
exe
cwd
comm
cmdline
fingerprint
unit
module
kind
signature
engine
```

Suppressed findings are still written to JSONL but are not notified and do not trigger CFM blocks.

CLI:

```bash
nxs exclusions list
nxs exclusions add --component integrity --field exe --regex '/usr/sbin/nginx \(deleted\)' --reason 'nginx upgrade'
nxs exclusions remove <id>

nxs finding suppress <id> --reason "known backup agent"
nxs finding unsuppress <id>
```

---

# Feature 0.2 — Maintenance Mode

Maintenance mode avoids alert storms during:

```text
package updates
kernel updates
cPanel updates
site migrations
bulk restores
WordPress mass updates
backup jobs
```

CLI:

```bash
nxs maintenance on --ttl 30m
nxs maintenance off
nxs maintenance status
```

During maintenance:

```text
scan normally
watch normally
log findings normally
mark maintenance_suppressed=true
do not notify
do not call CFM block API
auto-expire after TTL
```

---

# Feature 1 — Native Scan Engine

This remains the first functional scanning feature.

## Tiers

```text
Tier 0: ignore check
Tier 1: MD5/SHA256 malware hash
Tier 2: Aho-Corasick pattern match
Tier 3: go-yara + https://yarahq.github.io/ rules (core/extended/full)
Tier 4: typical shell/malware indicators (js lib obsfucation, base64 eval etc)
Tier 5: optional clamd connector
```

## Signature layout

```text
/var/lib/nxs/signatures/
scan for files in signatures/ directory. - auto detect theme
```

## CLI

```bash
nxs signatures status
nxs signatures reload
nxs signatures check <file>
nxs signatures add-ignore <hash>
nxs signatures test <sigfile>

nxs scan <file>
nxs scan --engine-only <file>
nxs scan --explain <file>
```

---

# Feature 2 — fanotify Monitor

fanotify is the real-time event source.

## Groups

```go
type WatchGroup uint8

const (
    GroupWeb WatchGroup = 1
    GroupSystem WatchGroup = 2
    GroupRuntime WatchGroup = 3
)
```

## GroupWeb

For malware scanning:

```text
/home
/tmp
/dev/shm
upload socket from CFM, optional
```

## GroupSystem

For integrity checks:

```text
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin
/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
/etc/systemd/system
/etc/profile.d
/etc/sudoers.d
/var/spool/cron
/lib/modules
/home/*/.ssh
/etc/ld.so.preload
```

## GroupRuntime

For runtime access/exec monitoring:

```text
/tmp
/var/tmp
/dev/shm
/home/*/public_html
/home/*/tmp
/home/*/.cache
/etc/shadow
/etc/gshadow
/root/.ssh
/etc/ssh/ssh_host_*_key
/home/*/.ssh/id_*
```

## fanotify failure behavior

fanotify failure must not stop NXS.

If unavailable:

```text
emit FANOTIFY_UNAVAILABLE
fall back to periodic scan
daemon continues
```

---

# Feature 3 — Scanner Pipeline

Pipeline:

```text
fanotify GroupWeb
periodic walk
upload socket
    ↓
filter
dedupe
native engine
optional yara
optional clamd
    ↓
finding
action decision
quarantine or clean
notify
optional CFM block
```

## Actions

```text
known standalone webshell -> quarantine
WP core/plugin/theme file -> attempt clean
unknown infected PHP      -> quarantine
HTML/JS phishing/skimmer  -> quarantine or clean depending confidence
```

## Quarantine

```text
/var/lib/nxs/quarantine/
  <timestamp>_<safe_path>
  <timestamp>_<safe_path>.meta.json
```

Always preserve:

```text
original path
uid/gid
mode
mtime
signature
engine
source
attacker IP if known
```

CLI:

```bash
nxs quarantine list
nxs quarantine show <id>
nxs quarantine restore <id>
```

---

# Feature 4 — Surgical PHP Cleaning

Purpose: remove injected malicious PHP while keeping the site online.

Strategies:

```text
@include injection
prepend injection
append injection
inline eval
base64 chains
chr()/pack()
hex variables
```

Always:

```text
backup before cleaning
write JSON sidecar
allow restore
report removed samples safely
```

CLI:

```bash
nxs clean file <path>
nxs clean restore <backup>
nxs clean explain <path>
```

---

# Feature 5 — WordPress & CMS Integrity

## WordPress core

Use official checksum API.

```text
detect WP root
read version.php
fetch checksum map
cache 7 days
compare core file MD5
emit WP_CORE_TAMPERED
```

## WordPress plugins

Phase 2:

```text
wordpress.org plugin checksums where available
fallback baseline for private/paid plugins
```

## Other CMS

```text
Joomla
Drupal
Magento 2
OpenCart
Composer-based apps
```

CLI:

```bash
nxs wp check <path>
nxs wp scan <wp-root>
nxs cms scan <root>
```

---

# Feature 6 — Database Scanning & Cleaning

## Targets

```text
WordPress users
WordPress posts
WordPress options
WordPress cron
future: Joomla/Drupal/Magento/OpenCart
```

## Safety

```text
read-only by default
dry-run support
mysqldump before any change
never auto-delete posts
mark spam posts as draft
injected users require config flag for auto-delete
```

CLI:

```bash
nxs db scan <user>
nxs db scan --all
nxs db clean <user> --dry-run
```

---

# Feature 7 — Real-Time Integrity Detector

This is the NXS home for integrity detection.

## Mechanisms

```text
fanotify GroupSystem:
  binary replacement
  .ko dropped
  cron planted
  systemd unit planted
  SSH key injected

fast poller, 5s:
  hidden processes
  hidden ports
  new kernel modules
  kallsyms rootkit strings

single-file watcher/poller:
  /etc/ld.so.preload
  /etc/passwd
  /etc/shadow
  /etc/sudoers
  /etc/ssh/sshd_config
```

## Additional checks

```text
/etc/ld.so.preload created/changed/removed
/etc/cron* changed
/var/spool/cron changed
/root/.ssh/authorized_keys changed
/home/*/.ssh/authorized_keys changed
new SUID/SGID file
new systemd service/timer
new enabled systemd unit/timer
new kernel module loaded
auditd stopped/disabled, optional
rsyslog stopped/disabled
suspicious executable in /tmp,/var/tmp,/dev/shm
deleted-but-running process
process cwd/exe under deleted path
cPanel updates disabled, optional
```

## Finding kinds

```text
LD_PRELOAD_CREATED
LD_PRELOAD_CHANGED
LD_PRELOAD_REMOVED

CRON_FILE_CREATED
CRON_FILE_CHANGED
USER_CRON_CHANGED

AUTHORIZED_KEY_ADDED
AUTHORIZED_KEY_REMOVED
ROOT_AUTHORIZED_KEYS_CHANGED
USER_AUTHORIZED_KEYS_CHANGED

SYSTEMD_UNIT_CREATED
SYSTEMD_UNIT_CHANGED
SYSTEMD_UNIT_ENABLED
SYSTEMD_TIMER_CREATED
SYSTEMD_TIMER_ENABLED

SUID_FILE_CREATED
SGID_FILE_CREATED
SUID_FILE_CHANGED
SGID_FILE_CHANGED

PROCESS_EXE_DELETED
PROCESS_CWD_DELETED
PROCESS_ROOT_DELETED

KERNEL_MODULE_LOADED
KERNEL_MODULE_UNLOADED
KALLSYMS_ROOTKIT
ROOTKIT_ARTIFACT
GSOCKET_BACKDOOR

RSYSLOG_STOPPED
RSYSLOG_DISABLED
AUDITD_STOPPED
AUDITD_DISABLED
CPANEL_UPDATES_DISABLED
```

## Evidence examples

Cron:

```text
path
old/new sha256
added/removed lines
line numbers
redacted secrets
defanged URLs
```

authorized_keys:

```text
key type
SHA256 fingerprint
comment
line number
never full key
```

systemd:

```text
unit name
unit path
enabled state
ExecStart samples
risk flags
```

SUID:

```text
path
sha256
mode
uid/gid
size
mtime
risk flags
```

deleted process:

```text
pid
ppid
uid
user
comm
cmdline
exe
cwd
```

---

# Feature 7.5 — Runtime Access Monitor

This is not Falco, auditd, or eBPF.

It is narrow fanotify-based runtime monitoring.

## Default mode

```text
observe only
fail open
do not block
do not deny
permission events always allow in v1
```

## Purpose

Detect:

```text
execution from /tmp
execution from /var/tmp
execution from /dev/shm
execution from /home/*/public_html
execution from /home/*/tmp
execution from /home/*/.cache
reads of /etc/shadow
reads of /etc/gshadow
reads of SSH private keys
suspicious file access by web users
```

## Package

```text
internal/runtime/
  events.go
  fanotify_linux.go
  fanotify_other.go
  classify.go
  proc.go
  hash.go
  policy.go
```

## Config

```ini
[runtime]
ENABLED = 0
BACKEND = fanotify
MODE = observe
FAIL_OPEN = 1
ALLOW_TIMEOUT = 500ms
HASH_FILES = 1
MAX_HASH_BYTES = 10485760
EVENT_BUFFER = 4096
NOTIFY = 1
NOTIFY_MIN_SEVERITY = high

EXEC_PATHS = /tmp,/var/tmp,/dev/shm,/home/*/public_html,/home/*/tmp,/home/*/.cache
SENSITIVE_READ_PATHS = /etc/shadow,/etc/gshadow,/root/.ssh,/etc/ssh/ssh_host_*_key,/home/*/.ssh/id_*
```

## Finding kinds

```text
RUNTIME_EXEC_TMP
RUNTIME_EXEC_VARTMP
RUNTIME_EXEC_DEVSHM
RUNTIME_EXEC_PUBLIC_HTML
RUNTIME_EXEC_HOME_CACHE

SENSITIVE_FILE_READ
SHADOW_READ
SENSITIVE_SSH_KEY_READ

FANOTIFY_OVERFLOW
FANOTIFY_ERROR
FANOTIFY_UNAVAILABLE
```

## Severity

```text
exec from /dev/shm                         high
exec from /tmp or /var/tmp                 high
exec from public_html                      high
exec from public_html by web user          critical
/etc/shadow read by non-root               critical
/etc/shadow read by php/perl/python/bash   critical
SSH private key read by unexpected process critical
fanotify overflow                          high
fanotify unavailable                       medium/high
```

## Evidence

```text
path
pid
ppid
uid
gid
user
group
comm
cmdline
exe
cwd
sha256
mode
decision=allow
fail_open=true
risk_flags
```

---

# Feature 8 — Notification System

NXS has its own notifier.

Do not reuse CFM `notify.conf`.

## Config

```ini
[notify]
ENABLED = 1
DEFAULT_COOLDOWN = 30m
JSONL_PATH = /var/log/nxs/notify.log.jsonl

[notify_channel "sendmail"]
TYPE = sendmail
ENABLED = 1
PATH = /usr/sbin/sendmail
TO = logs@server

[notify_channel "slack"]
TYPE = slack_webhook
ENABLED = 0
WEBHOOK_URL = ${ENV:NXS_SLACK_WEBHOOK}
MENTION = @chris
USERNAME = NXS

[notify_route "*"]
CHANNELS = sendmail
MIN_SEVERITY = high
COOLDOWN = 30m

[notify_route "malware"]
CHANNELS = sendmail,slack
MIN_SEVERITY = high
COOLDOWN = 10m

[notify_route "integrity"]
CHANNELS = sendmail,slack
MIN_SEVERITY = high
COOLDOWN = 15m

[notify_route "runtime"]
CHANNELS = sendmail,slack
MIN_SEVERITY = high
COOLDOWN = 5m

[notify_route "SHADOW_READ"]
CHANNELS = sendmail,slack
MIN_SEVERITY = critical
COOLDOWN = 2m

[notify_route "ROOTKIT_ARTIFACT"]
CHANNELS = sendmail,slack
MIN_SEVERITY = critical
COOLDOWN = 2m
```

Notifier body should focus on:

```text
host
severity
component
kind
path
pid/user/cmdline
signature
action/action_result
safe sample/diff
exclude hint
```

---

# Feature 9 — CFM Client

NXS can call CFM, but must not depend on it.

```text
internal/cfmclient/
  client.go
  block.go
  health.go
```

## Blockable finding types

```text
webshell
dropper
phishing_upload
rootkit_artifact with source IP
runtime_exec with source IP
binary_tampered with source IP
```

If no attacker IP exists, do not block.

If CFM is unavailable:

```text
log cfm_block_attempted=true
cfm_block_result=failed
continue NXS actions
```

---

# nxs.conf high-level draft

```ini
[main]
ENABLED = 1
HOSTNAME =
DATA_DIR = /var/lib/nxs
LOG_DIR = /var/log/nxs
RUN_DIR = /var/run/nxs

[findings]
LOG_PATH = /var/log/nxs/findings.log
STATE_PATH = /var/lib/nxs/state/findings.json
NOTIFY = 1
NOTIFY_MIN_SEVERITY = high
NOTIFY_COOLDOWN = 30m

[samples]
MAX_DIFF_LINES = 20
MAX_LINE_LENGTH = 300
MAX_SAMPLES_PER_FINDING = 10
REDACT_SECRETS = 1
URL_DEFANG = 1
STORE_FULL_DIFF = 0

[maintenance]
STATE_PATH = /var/lib/nxs/state/maintenance.json

[engine]
ENABLED = 1
SIG_DIR = /var/lib/nxs/signatures
YARA_ENABLED = 1
YARA_RULES_DIR = /var/lib/clamav
CLAMD_ENABLED = 1
CLAMD_SOCKET = /var/run/clamav/clamd.sock
CLAMD_TIMEOUT = 10s
CLAMD_FALLBACK_ONLY = 1

[scanner]
ENABLED = 1
FANOTIFY_ENABLED = 1
WATCH_PATHS = /home,/tmp,/dev/shm
PERIODIC_ENABLED = 1
PERIODIC_EVERY = 6h
PERIODIC_START_HOUR = 2
UPLOAD_SCAN_ENABLED = 1
UPLOAD_SOCKET = /var/run/nxs/scan.sock
WATCH_EXTENSIONS = .php,.phtml,.php5,.php7,.html,.htm,.js,.htaccess,.user.ini
MAX_FILE_SIZE = 2097152
QUARANTINE_DIR = /var/lib/nxs/quarantine
AUTO_CLEAN = 1
QUEUE_SIZE = 1024
MAX_WORKERS = 4

[integrity]
ENABLED = 1
PROCESS_CHECK = 1
PORT_CHECK = 1
MODULE_CHECK = 1
KALLSYMS_CHECK = 1
PRELOAD_CHECK = 1
PASSWD_CHECK = 1
SUDOERS_CHECK = 1
SSHD_CONFIG_CHECK = 1
ARTIFACT_SCAN = 1
CRON_CHECK = 1
SYSTEMD_CHECK = 1
SSH_KEYS_CHECK = 1
SUID_SGID_CHECK = 1
TMP_EXEC_CHECK = 1
DELETED_PROCESS_CHECK = 1
SERVICE_CHECK = 1
CPANEL_UPDATE_CHECK = 1

[integrity_services]
REQUIRE_AUDITD = 0
REQUIRE_RSYSLOG = 1
EXPECT_CPANEL_UPDATES_ENABLED = 1

[runtime]
ENABLED = 0
BACKEND = fanotify
MODE = observe
FAIL_OPEN = 1
ALLOW_TIMEOUT = 500ms
HASH_FILES = 1
MAX_HASH_BYTES = 10485760
EVENT_BUFFER = 4096
NOTIFY = 1
NOTIFY_MIN_SEVERITY = high
EXEC_PATHS = /tmp,/var/tmp,/dev/shm,/home/*/public_html,/home/*/tmp,/home/*/.cache
SENSITIVE_READ_PATHS = /etc/shadow,/etc/gshadow,/root/.ssh,/etc/ssh/ssh_host_*_key,/home/*/.ssh/id_*

[dbscanner]
ENABLED = 1
EVERY = 24h
AUTO_CLEAN_USERS = 0
AUTO_DRAFT_POSTS = 1
SCAN_PREFIXES = wp_

[cfm]
ENABLED = 0
API_URL = https://127.0.0.1:6061
API_TOKEN =
BLOCK_TTL = 24h
BLOCK_ON = webshell,dropper,rootkit_artifact,binary_tampered
```

---

# CLI roadmap

## Core

```bash
nxs version
nxs daemon
nxs status
```

## Findings

```bash
nxs findings --last 20
nxs finding show <id>
nxs finding suppress <id> --reason "..."
nxs finding unsuppress <id>
```

## Exclusions

```bash
nxs exclusions list
nxs exclusions add --component integrity --field path --equals /path --reason "..."
nxs exclusions add --component runtime --field exe --regex '...' --reason "..."
nxs exclusions remove <id>
```

## Maintenance

```bash
nxs maintenance on --ttl 30m
nxs maintenance off
nxs maintenance status
```

## Signatures

```bash
nxs signatures status
nxs signatures reload
nxs signatures check <file>
nxs signatures add-ignore <hash>
nxs signatures test <sigfile>
```

## Scanning

```bash
nxs scan <file>
nxs scan --engine-only <file>
nxs scan --explain <file>
nxs scan-dir <path>
```

## Quarantine

```bash
nxs quarantine list
nxs quarantine show <id>
nxs quarantine restore <id>
```

## Cleaning

```bash
nxs clean file <path>
nxs clean restore <backup>
nxs clean explain <path>
```

## WordPress/CMS

```bash
nxs wp check <path>
nxs wp scan <wp-root>
nxs cms scan <root>
```

## Database

```bash
nxs db scan <user>
nxs db scan --all
nxs db clean <user> --dry-run
```

## Integrity

```bash
nxs integrity baseline
nxs integrity baseline --refresh --reason "..."
nxs integrity status
nxs integrity scan
nxs integrity scan --json
```

## Runtime

```bash
nxs runtime status
nxs runtime test-policy <path>
```

---

# Dependency graph

```text
Feature 0 — Finding/Event Framework
    ↓
Feature 1 — Native Scan Engine
    ↓
Feature 2 — fanotify Monitor
    ↓
Feature 3 — Scanner Pipeline
    ├── Feature 4 — Surgical Cleaning
    ├── Feature 5 — WordPress/CMS Integrity
    ├── Feature 6 — Database Scanner
    ├── Feature 7 — Real-Time Integrity Detector
    └── Feature 7.5 — Runtime Access Monitor

Feature 8 — Notify uses Feature 0
Feature 9 — CFM client uses Feature 0 + scanner/integrity findings
Feature 10 — PAM remains deferred
```

---

# First implementation order

```text
0. Project skeleton
1. Feature 0 — Finding/Event Framework
2. Feature 1 — Native Scan Engine
3. Feature 2 — fanotify Monitor
4. Feature 3 — Scanner Pipeline
5. Quarantine basics
6. Notify basics
7. CFM client basics
8. Feature 7 — Integrity basics
9. Feature 7.5 — Runtime monitor observe-only
10. Cleaner
11. WordPress/CMS integrity
12. Database scanner
```

## Beta session checklist

```text
Project skeleton:
[x] go mod init github.com/chrismfz/nxs
[x] add github.com/cloudflare/ahocorasick
[ ] add golang.org/x/sys              (removed; stdlib syscall used instead)
[ ] add MySQL driver                   (deferred — DB scanner not started)
[x] create cmd/nxs/main.go
[x] create internal/config
[x] create internal/logging
[x] create configs/nxs.conf.example
[x] create configs/nxs.conf
[x] create configs/hashdb.csv          (header-only; operators populate)
[x] create configs/signatures/         (empty dir; operators populate)
[x] create Makefile                    (aligned with CFM: stage-pkgroot, stage-rpm,
                                        rpm_prep_dirs, rpm_spec_version, sync, release)
[x] create packaging/rpm/SPECS/nxs.spec
[x] create packaging/debian/DEBIAN/
[x] create packaging/nxs.service       (ExecStart=nxs daemon, journal output)
[x] create LICENSE                     (MIT)
[x] create docs/roadmaps/roadmap-v2.md

Feature 0 — Finding/Event Framework:
[x] internal/events/event.go           (Finding, Sample, Diff structs; NewFinding)
[x] internal/events/jsonl.go           (JSONLWriter, flock, ReadFiltered)
[x] internal/events/state.go           (StateStore, atomic rename flush)
[x] internal/events/severity.go        (SeverityRank, MeetsSeverity)
[x] internal/events/samples.go         (ExtractSamples — byte windows at match offset)
[x] internal/events/redact.go          (RedactFinding, URL defang)
[x] internal/exclusions/               (ExclusionSet, path/prefix/glob/hash/regex match,
                                        Add/Remove/List, atomic rename)
[x] internal/maintenance/              (Schedule, InMaintenance, AddWindow/RemoveWindow)
[x] nxs findings CLI                   (--since, --severity, --limit, --json)
[x] nxs exclusions CLI                 (list / add --type --value --reason / remove)
[x] nxs maintenance CLI                (list / add --ttl / remove)

Feature 1 — Native Scan Engine:
[x] internal/engine/loader.go          (HashIndex from CSV, MD5+SHA256, O(1) lookup)
[x] internal/engine/signatures.go      (*.sig loader, BuildACMatcher)
[x] internal/engine/builder.go         (Engine.ScanFile: hash→AC→YARA tiers;
                                        Engine.ScanDir: WalkDir goroutine)
[x] internal/engine/reload.go          (SIGHUP reload of hash DB + sigs + YARA)
[x] internal/engine/stats.go           (atomic Stats snapshot)
[x] internal/engine/yara.go            (YARA-X Tier 3 via yr subprocess, NDJSON output,
                                        graceful fallback when yr absent)

Feature 2 — fanotify Monitor:
[x] internal/filewatch/monitor.go      (Monitor interface, New factory)
[x] internal/filewatch/monitor_linux.go (probes fanotify_init; falls back gracefully)
[x] internal/filewatch/monitor_other.go (non-Linux stub)
[x] internal/filewatch/watcher.go      (fallbackMonitor — nil channel → periodic scan)
[x] internal/filewatch/filter.go       (FilterPath: skip /proc /sys /dev)
[ ] real-time fanotify loop            (deferred post-beta)

Feature 3 — Scanner Pipeline:
[x] internal/scanner/pipeline.go       (RunScan: maintenance→ScanDir→exclusions→
                                        state→action→JSONL→notify-eligible)
[x] internal/scanner/quarantine.go     (chmod/copy/move modes, .nxsmeta.json sidecar, List)
[x] internal/scanner/action.go         (Decide: critical/high → quarantine)
[x] internal/scanner/dedup.go          (DedupFindings within a scan run)
[x] internal/scanner/filter.go         (FilterBySeverity, FilterByPath)
[x] internal/scanner/periodic.go       (goroutine loop, TriggerNow via channel)
[x] nxs scan CLI                       (--severity, --json, multi-path)
[x] nxs quarantine list CLI

Feature 6 — Notify:
[x] internal/notify/notify.go          (Notifier interface, New factory)
[x] internal/notify/sendmail.go        (pipes to /usr/sbin/sendmail -t)
[x] internal/notify/smtp.go            (net/smtp stdlib, STARTTLS/TLS/plain, PLAIN auth)
[x] internal/notify/slack.go           (net/http POST to incoming webhook, by severity)
[x] internal/notify/template.go        (shared subject/body/email builder)
[x] internal/notify/dedupe.go          (NotifyStateStore: per-finding cooldown)

Daemon:
[x] nxs daemon                         (signal loop: SIGHUP→reload+scan, SIGTERM→shutdown)
[x] nxs version CLI

Stub packages (directory structure, post-beta):
[x] internal/cfmclient/               (thin HTTP client to CFM block API)
[x] internal/clam/                    (clamd connector)
[x] internal/cleaner/                 (surgical PHP injection cleaner)
[x] internal/wpintegrity/             (WordPress core/plugin checksum)
[x] internal/cmsintegrity/            (Joomla/Drupal/Magento/OpenCart)
[x] internal/dbscanner/               (WordPress DB malware scanner)
[x] internal/integrity/               (real-time integrity detector)
[x] internal/runtime/                 (fanotify runtime access monitor)

Still to implement (post-beta):
[ ] fanotify GroupWeb real-time loop
[ ] fanotify GroupSystem (integrity events)
[ ] fanotify GroupRuntime (exec/read monitor)
[ ] YARA Forge rules download/management
[ ] clamd connector (internal/clam)
[ ] surgical PHP cleaner (internal/cleaner)
[ ] WordPress/CMS integrity (internal/wpintegrity, internal/cmsintegrity)
[ ] database scanner (internal/dbscanner)
[ ] real-time integrity detector (internal/integrity)
[ ] CFM block API client (internal/cfmclient)
[ ] nxs wp / nxs cms / nxs db CLI
[ ] nxs integrity CLI
[ ] nxs runtime CLI
[ ] nxs signatures CLI (status/reload/check/test)
[ ] quarantine restore
[ ] MySQL driver (when DB scanner starts)
```

---

# Final recommendation

Keep CFM focused:

```text
network / WAF / challenge / login failures / nftables
```

Let NXS become the deeper host-security project:

```text
fanotify / malware / filesystem / integrity / cleanup / runtime access
```

Together:

```text
CFM blocks traffic.
NXS finds what landed on disk and what changed on the host.
```
