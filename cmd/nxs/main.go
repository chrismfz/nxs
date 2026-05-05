package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrismfz/nxs/internal/config"
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

	_ = debug

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		// Fall back to defaults if config file is absent during development
		cfg = config.Default()
		fmt.Fprintf(os.Stderr, "nxs: config load warning: %v — using defaults\n", err)
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "nxs %s — use 'nxs --help' or 'nxs daemon' to start\n", Version)
		fmt.Fprintf(os.Stderr, "config: %s | data: %s | logs: %s\n",
			*cfgPath, cfg.Main.DataDir, cfg.Main.LogDir)
		os.Exit(0)
	}

	// Subcommand dispatch — wired fully in Step 9.
	fmt.Fprintf(os.Stderr, "nxs: subcommand %q not yet implemented\n", args[0])
	os.Exit(1)
}
