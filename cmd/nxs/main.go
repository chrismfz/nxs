package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/chrismfz/nxs/internal/config"
	"github.com/chrismfz/nxs/internal/events"
	"github.com/chrismfz/nxs/internal/exclusions"
	"github.com/chrismfz/nxs/internal/filewatch"
	"github.com/chrismfz/nxs/internal/logging"
	"github.com/chrismfz/nxs/internal/maintenance"
	"github.com/chrismfz/nxs/internal/notify"
	"github.com/chrismfz/nxs/internal/scanner"
	"github.com/chrismfz/nxs/internal/setup"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	var (
		cfgPath = flag.String("config", "/etc/nxs/nxs.conf", "path to nxs.conf")
		debug   = flag.Bool("debug", false, "enable debug logging")
		version = flag.Bool("version", false, "print version and exit")
	)
	flag.StringVar(cfgPath, "c", "/etc/nxs/nxs.conf", "path to nxs.conf (shorthand)")
	flag.Parse()

	if *version {
		fmt.Printf("nxs %s (built %s)\n", Version, BuildTime)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		cfg = config.Default()
		fmt.Fprintf(os.Stderr, "nxs: config warning: %v — using defaults\n", err)
	}
	_ = debug

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(0)
	}

	log, err := logging.New(cfg)
	if err != nil {
		// If log dir isn't writable (e.g. non-root), use nop for CLI commands
		log = logging.NewNop()
	}

	switch args[0] {
	case "daemon":
		cmdDaemon(cfg, log)
	case "scan":
		cmdScan(cfg, log, args[1:])
	case "findings":
		cmdFindings(cfg, args[1:])
	case "quarantine":
		cmdQuarantine(cfg, log, args[1:])
	case "exclusions":
		cmdExclusions(cfg, args[1:])
	case "maintenance":
		cmdMaintenance(cfg, args[1:])
	case "signatures":
		cmdSignatures(cfg, args[1:])
	case "version":
		fmt.Printf("nxs %s (built %s)\n", Version, BuildTime)
	default:
		fmt.Fprintf(os.Stderr, "nxs: unknown subcommand %q\n\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

// ─── daemon ──────────────────────────────────────────────────────────────────

func cmdDaemon(cfg *config.Config, log *logging.Logger) {
	log.Info("nxs daemon starting", "version", Version)

	pipeline, err := scanner.NewPipeline(cfg, log)
	if err != nil {
		log.Error("pipeline init failed", "err", err)
		os.Exit(1)
	}
	defer pipeline.Close()

	notifier := notify.New(cfg, log)
	_ = notifier

	monitor := filewatch.New(cfg, log)
	periodic := scanner.NewPeriodic(pipeline, cfg, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor (may return nil channel — falls back to periodic)
	monCh, err := monitor.Start(ctx)
	if err != nil || monCh == nil {
		log.Info("real-time monitor unavailable — using periodic scan only")
	}

	go periodic.Start(ctx)
	go pipeline.Engine().WatchReload(ctx)

	// Write PID file so `nxs signatures update` can signal us.
	pidFile := filepath.Join(cfg.Main.RunDir, "nxs.pid")
	if err := writePIDFile(pidFile); err != nil {
		log.Warn("could not write PID file", "path", pidFile, "err", err)
	} else {
		defer os.Remove(pidFile)
	}

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	log.Info("nxs daemon started", "pid", os.Getpid())

	for sig := range sigCh {
		switch sig {
		case syscall.SIGHUP:
			log.Info("SIGHUP — triggering immediate scan and reload")
			periodic.TriggerNow()
		case syscall.SIGTERM, syscall.SIGINT:
			log.Info("shutdown signal received", "signal", sig)
			cancel()
			// Give goroutines 30s to finish
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer shutdownCancel()
			<-shutdownCtx.Done()
			log.Info("nxs daemon stopped")
			return
		}
	}
}

// ─── scan ─────────────────────────────────────────────────────────────────────

func cmdScan(cfg *config.Config, log *logging.Logger, args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	minSev := fs.String("severity", "info", "minimum severity to show")
	asJSON := fs.Bool("json", false, "output raw JSONL")
	_ = fs.Parse(args)

	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nxs scan [--severity high] [--json] <path>...")
		os.Exit(1)
	}

	pipeline, err := scanner.NewPipeline(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
		os.Exit(1)
	}
	defer pipeline.Close()

	ctx := context.Background()
	findings, err := pipeline.RunScan(ctx, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nxs: scan error: %v\n", err)
		os.Exit(1)
	}

	findings = scanner.FilterBySeverity(findings, *minSev)
	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "nxs: no findings (severity>=%s)\n", *minSev)
		return
	}

	printFindings(findings, *asJSON)
}

// ─── findings ────────────────────────────────────────────────────────────────

func cmdFindings(cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("findings", flag.ExitOnError)
	since := fs.String("since", "24h", "show findings from last duration (e.g. 1h, 7d)")
	minSev := fs.String("severity", "", "minimum severity filter")
	limit := fs.Int("limit", 100, "maximum findings to show")
	asJSON := fs.Bool("json", false, "output raw JSONL")
	_ = fs.Parse(args)

	dur, err := parseDuration(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nxs: invalid --since %q: %v\n", *since, err)
		os.Exit(1)
	}

	sinceTime := time.Now().Add(-dur)
	findings, err := events.ReadFindings(cfg.Findings.LogPath, sinceTime, *minSev, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nxs: read findings: %v\n", err)
		os.Exit(1)
	}
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "nxs: no findings")
		return
	}
	printFindings(findings, *asJSON)
}

// ─── quarantine ───────────────────────────────────────────────────────────────

func cmdQuarantine(cfg *config.Config, log *logging.Logger, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nxs quarantine <list|restore>")
		os.Exit(1)
	}
	q, err := scanner.NewQuarantine(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		entries, err := q.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
			os.Exit(1)
		}
		if len(entries) == 0 {
			fmt.Println("No quarantined files.")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tMODE\tORIG PATH\tDATE")
		for _, e := range entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
				e.ID, e.Mode, e.OrigPath, e.QuarantinedAt.Format("2006-01-02 15:04"))
		}
		tw.Flush()
	case "restore":
		fmt.Fprintln(os.Stderr, "nxs: quarantine restore — not yet implemented")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "nxs: unknown quarantine subcommand %q\n", args[0])
		os.Exit(1)
	}
}

// ─── exclusions ───────────────────────────────────────────────────────────────

func cmdExclusions(cfg *config.Config, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nxs exclusions <list|add|remove>")
		os.Exit(1)
	}
	path := cfg.Exclusions.File
	switch args[0] {
	case "list":
		items, err := exclusions.List(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
			os.Exit(1)
		}
		if len(items) == 0 {
			fmt.Println("No exclusions.")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTYPE\tVALUE\tREASON")
		for _, e := range items {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.ID, e.Type, e.Value, e.Reason)
		}
		tw.Flush()

	case "add":
		fs := flag.NewFlagSet("exclusions add", flag.ExitOnError)
		exclType := fs.String("type", "path", "exclusion type: path,prefix,glob,hash,regex")
		value := fs.String("value", "", "value to match")
		component := fs.String("component", "", "component (optional)")
		kind := fs.String("kind", "", "finding kind (optional)")
		reason := fs.String("reason", "", "reason for exclusion")
		_ = fs.Parse(args[1:])
		if *value == "" && fs.NArg() > 0 {
			*value = fs.Arg(0)
		}
		if *value == "" {
			fmt.Fprintln(os.Stderr, "nxs: --value required")
			os.Exit(1)
		}
		e, err := exclusions.Add(path, exclusions.ExclusionType(*exclType), *value, *component, *kind, *reason)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Exclusion added: %s\n", e.ID)

	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: nxs exclusions remove <id>")
			os.Exit(1)
		}
		if err := exclusions.Remove(path, args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Exclusion %s removed.\n", args[1])

	default:
		fmt.Fprintf(os.Stderr, "nxs: unknown exclusions subcommand %q\n", args[0])
		os.Exit(1)
	}
}

// ─── maintenance ─────────────────────────────────────────────────────────────

func cmdMaintenance(cfg *config.Config, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nxs maintenance <list|add|remove>")
		os.Exit(1)
	}
	path := cfg.Maintenance.StatePath
	switch args[0] {
	case "list":
		sched, err := maintenance.Load(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
			os.Exit(1)
		}
		windows := sched.Windows()
		if len(windows) == 0 {
			fmt.Println("No maintenance windows.")
			return
		}
		now := time.Now()
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSTARTS\tENDS\tACTIVE\tREASON")
		for _, w := range windows {
			active := "-"
			if !now.Before(w.Start) && now.Before(w.End) {
				active = "YES"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				w.Name,
				w.Start.Format("2006-01-02 15:04"),
				w.End.Format("2006-01-02 15:04"),
				active, w.Reason)
		}
		tw.Flush()

	case "add":
		fs := flag.NewFlagSet("maintenance add", flag.ExitOnError)
		name := fs.String("name", "", "window name")
		ttl := fs.String("ttl", "1h", "duration (e.g. 30m, 2h)")
		reason := fs.String("reason", "", "reason")
		_ = fs.Parse(args[1:])
		if *name == "" && fs.NArg() > 0 {
			*name = fs.Arg(0)
		}
		if *name == "" {
			*name = "manual"
		}
		dur, err := time.ParseDuration(*ttl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nxs: invalid --ttl %q: %v\n", *ttl, err)
			os.Exit(1)
		}
		now := time.Now().UTC()
		w := &maintenance.Window{
			Name:   *name,
			Start:  now,
			End:    now.Add(dur),
			Reason: *reason,
		}
		if err := maintenance.AddWindow(path, w); err != nil {
			fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Maintenance window %q added until %s\n", *name, w.End.Format("15:04 UTC"))

	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: nxs maintenance remove <name>")
			os.Exit(1)
		}
		if err := maintenance.RemoveWindow(path, args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "nxs: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Maintenance window %q removed.\n", args[1])

	default:
		fmt.Fprintf(os.Stderr, "nxs: unknown maintenance subcommand %q\n", args[0])
		os.Exit(1)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func printFindings(findings []*events.Finding, asJSON bool) {
	if asJSON {
		for _, f := range findings {
			fmt.Printf("%s\n", mustJSON(f))
		}
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tSEVERITY\tKIND\tPATH\tMESSAGE")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			f.TS.Format("01-02 15:04"),
			strings.ToUpper(f.Severity),
			f.Kind,
			f.Path,
			truncate(f.Message, 60),
		)
	}
	tw.Flush()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `nxs %s — iNtegrity eXploit Scanner

Usage: nxs [--config <path>] <subcommand> [flags]

Subcommands:
  daemon                          Start daemon (systemd entry point)
  scan [--severity] [--json] <path>...
                                  Scan file or directory
  findings [--since 24h] [--severity high] [--limit 100] [--json]
                                  Query findings log
  quarantine list                 List quarantined files
  exclusions list|add|remove      Manage scan exclusions
  maintenance list|add|remove     Manage maintenance windows
  signatures status               Show yr + YARA rules status
  signatures update               Install/update yr binary + YARA Forge rules
  version                         Print version

Global flags:
  --config / -c <path>  Config file (default /etc/nxs/nxs.conf)
  --debug               Enable debug logging
  --version             Print version and exit
`, Version)
}

// ─── signatures ──────────────────────────────────────────────────────────────

func cmdSignatures(cfg *config.Config, args []string) {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}

	yaraBin := cfg.Engine.YARABinary
	if yaraBin == "" {
		yaraBin = "yr"
	}
	sigDir := cfg.Engine.SigDir
	if sigDir == "" {
		sigDir = "/var/lib/nxs/signatures"
	}
	bundledDir := "/usr/share/nxs/signatures"

	progress := func(msg string) { fmt.Println(" ", msg) }

	switch sub {
	case "status":
		fmt.Println("── yr (yara-x) ──────────────────────────────")
		if path, err := setup.LookupYR(yaraBin); err == nil {
			ver, _ := setup.YARXVersion(path)
			fmt.Printf("  binary : %s\n", path)
			fmt.Printf("  version: %s\n", ver)
		} else {
			fmt.Printf("  binary : not found (%s)\n", yaraBin)
			fmt.Println("  hint   : run `nxs signatures update` to install")
		}
		fmt.Println("── signatures ───────────────────────────────")
		nbFiles, _ := setup.CountRuleFiles(bundledDir)
		nbRules, _ := setup.CountRules(bundledDir)
		if nbFiles > 0 {
			fmt.Printf("  bundled: %s (%d .yar/.yara, %d rules)\n", bundledDir, nbFiles, nbRules)
		}
		nFiles, _ := setup.CountRuleFiles(sigDir)
		nRules, _ := setup.CountRules(sigDir)
		nHDB, _ := setup.CountSigFiles(sigDir, ".hdb", ".hsb")
		nNDB, _ := setup.CountSigFiles(sigDir, ".ndb")
		nSig, _ := setup.CountSigFiles(sigDir, ".sig")
		nCSV, _ := setup.CountSigFiles(sigDir, ".csv")
		if nFiles+nHDB+nNDB+nSig+nCSV > 0 {
			fmt.Printf("  sig_dir: %s\n", sigDir)
			if nFiles > 0 {
				fmt.Printf("    yara : %d files, %d rules\n", nFiles, nRules)
			}
			if nHDB > 0 {
				fmt.Printf("    hash : %d .hdb/.hsb files\n", nHDB)
			}
			if nNDB > 0 {
				fmt.Printf("    ndb  : %d .ndb files\n", nNDB)
			}
			if nSig > 0 {
				fmt.Printf("    ac   : %d .sig files\n", nSig)
			}
			if nCSV > 0 {
				fmt.Printf("    csv  : %d .csv files\n", nCSV)
			}
		} else {
			fmt.Printf("  sig_dir: %s (empty or missing)\n", sigDir)
			fmt.Println("  hint   : run `nxs signatures update` to download YARA Forge rules")
		}
		fmt.Printf("  total  : %d YARA rules across %d files\n", nbRules+nRules, nbFiles+nFiles)

	case "setup", "update":
		fmt.Println("Updating YARA-X and YARA Forge rules...")

		installBin := yaraBin
		if installBin == "yr" {
			installBin = "/usr/local/bin/yr"
		}

		if _, err := setup.LookupYR(yaraBin); err != nil {
			fmt.Printf("Downloading yr → %s\n", installBin)
			if err := setup.InstallYARAX(installBin, progress); err != nil {
				fmt.Fprintf(os.Stderr, "nxs: failed to install yr: %v\n", err)
				fmt.Fprintf(os.Stderr, "     You can install it manually: https://github.com/VirusTotal/yara-x/releases\n")
			} else {
				fmt.Printf("  yr installed: %s\n", installBin)
			}
		} else {
			fmt.Printf("  yr already installed: %s (skipping)\n", yaraBin)
		}

		fmt.Printf("Downloading YARA Forge core rules → %s\n", sigDir)
		if err := setup.InstallYARAForge(sigDir, progress); err != nil {
			fmt.Fprintf(os.Stderr, "nxs: failed to download YARA Forge rules: %v\n", err)
			fmt.Fprintf(os.Stderr, "     Download manually from https://github.com/YARAHQ/yara-forge/releases\n")
		}

		if len(cfg.Signatures.DatabaseURLs) > 0 {
			fmt.Printf("Downloading %d configured signature database(s) → %s\n",
				len(cfg.Signatures.DatabaseURLs), sigDir)
			dl, skip, fail := setup.DownloadDBs(cfg.Signatures.DatabaseURLs, sigDir, progress)
			fmt.Printf("  downloaded: %d  up-to-date: %d  failed: %d\n", dl, skip, fail)
		}

		// Signal the running daemon to reload its engine with the new signatures.
		pidFile := filepath.Join(cfg.Main.RunDir, "nxs.pid")
		if err := signalDaemon(pidFile, syscall.SIGHUP); err == nil {
			fmt.Println("Daemon signalled — reloading signatures (no restart needed).")
		} else {
			fmt.Println("Done. Daemon not running; signatures will load on next start.")
		}

	default:
		fmt.Fprintf(os.Stderr, "nxs signatures: unknown action %q\n", sub)
		fmt.Fprintln(os.Stderr, "Usage: nxs signatures status|update")
		os.Exit(1)
	}
}

// writePIDFile atomically writes the current process PID to path.
func writePIDFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// signalDaemon reads the PID file at path and sends sig to that process.
func signalDaemon(pidFile string, sig syscall.Signal) error {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return err
	}
	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return err
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Signal(sig)
}

// parseDuration handles "7d" in addition to standard Go durations.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var n int
		if _, err := fmt.Sscanf(days, "%d", &n); err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
