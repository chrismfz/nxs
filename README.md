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

## Quick start (post-beta)

```bash
# Install
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

## CLI overview

```bash
nxs daemon                        # systemd entry point
nxs scan <path>                   # scan file or directory
nxs findings [--since 24h]        # query findings log
nxs quarantine list               # list quarantined files
nxs exclusions list|add|remove    # manage exclusions
nxs maintenance list|add|remove   # manage maintenance windows
nxs signatures status|reload      # manage scan signatures
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
