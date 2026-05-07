package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreflightYARRuleFilesAllowsDuplicatesAcrossNamespaces(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "bundled.yar")
	local := filepath.Join(dir, "local.yar")
	if err := os.WriteFile(bundled, []byte("rule SameName { condition: true }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("rule SameName { condition: true }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := preflightYARRuleFiles([]yaraRuleFile{
		{Path: bundled, OriginalPath: bundled, Source: "bundled", Namespace: "bundled"},
		{Path: local, OriginalPath: local, Source: "local", Namespace: "local"},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.ActiveRules != 2 || report.DuplicateSkipped != 0 {
		t.Fatalf("expected both duplicate names to remain active across namespaces, active=%d duplicates=%d", report.ActiveRules, report.DuplicateSkipped)
	}
}

func TestPreflightYARRuleFilesFallsBackToSharedNamespaceDuplicates(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "bundled.yar")
	local := filepath.Join(dir, "local.yar")
	if err := os.WriteFile(bundled, []byte("rule SameName { condition: true }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, []byte("rule SameName { condition: true }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := preflightYARRuleFiles([]yaraRuleFile{
		{Path: bundled, OriginalPath: bundled, Source: "bundled", Namespace: "bundled"},
		{Path: local, OriginalPath: local, Source: "local", Namespace: "local"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.ActiveRules != 1 || report.DuplicateSkipped != 1 {
		t.Fatalf("expected shared-namespace duplicate filtering fallback, active=%d duplicates=%d", report.ActiveRules, report.DuplicateSkipped)
	}
}

func TestYaraRuleFileScanArgPrefixesNamespaceWhenSupported(t *testing.T) {
	file := yaraRuleFile{Path: "/rules/example.yar", Namespace: "yara_forge"}
	if got := file.ScanArg(true); got != "yara_forge:/rules/example.yar" {
		t.Fatalf("unexpected namespace scan arg: %q", got)
	}
	if got := file.ScanArg(false); got != "/rules/example.yar" {
		t.Fatalf("unexpected fallback scan arg: %q", got)
	}
}
