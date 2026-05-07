package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreflightYARRulesSkipsDuplicateDeclarations(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.yar")
	second := filepath.Join(dir, "b.yara")
	if err := os.WriteFile(first, []byte(`rule KeepMe { condition: true }
private rule Dup { condition: true }
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte(`global rule Dup { condition: true }
rule Other { condition: true }
`), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := PreflightYARRules([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalRules != 4 || report.ActiveRules != 3 || report.DuplicateSkipped != 1 || report.ParseFailed != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if got := report.Duplicates[0]; got.File != second || got.Name != "Dup" || got.OriginalFile != first {
		t.Fatalf("unexpected duplicate: %+v", got)
	}
}

func TestParseYARRuleDeclarationsIgnoresCommentsStringsAndRuleBodies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yar")
	content := `// rule Commented { condition: true }
rule Real {
  strings:
    $a = "rule NotReal"
    $b = /rule AlsoNotReal/
  condition:
    true
}
/* private rule Blocked { condition: true } */
private rule PrivateOne { condition: true }
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	decls, err := ParseYARRuleDeclarations(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(decls) != 2 || decls[0].Name != "Real" || decls[1].Name != "PrivateOne" || !decls[1].Private {
		t.Fatalf("unexpected declarations: %+v", decls)
	}
}

func TestFilterYARRuleFileDropsOnlySkippedDuplicateBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yar")
	out := filepath.Join(dir, "filtered.yar")
	content := `rule Dup { condition: true }
private rule Dup { condition: true }
rule Keep { condition: true }
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	report, err := PreflightYARRules([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if err := FilterYARRuleFile(path, out, report.Declarations); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	filtered := string(data)
	if strings.Count(filtered, "rule Dup") != 1 || strings.Count(filtered, "private rule Dup") != 0 || strings.Count(filtered, "rule Keep") != 1 {
		t.Fatalf("expected duplicate file copy to keep first duplicate and unrelated rule, got:\n%s", filtered)
	}
	if !strings.Contains(filtered, "skipped duplicate YARA rule") {
		t.Fatalf("expected skip marker, got:\n%s", filtered)
	}
}
