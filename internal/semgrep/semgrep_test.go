package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSemgrep writes an executable shell script standing in for the real
// semgrep binary, so these tests don't require semgrep (and Python) to be
// installed to run `go test`. It asserts nothing about output correctness
// beyond what's encoded in stdout/exitCode - the real semgrep integration
// was verified manually (see docs/FINDINGS.md) since that's an external
// tool's behavior, not Scryer's own logic to unit test.
func fakeSemgrep(t *testing.T, stdout string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-semgrep.sh")
	script := "#!/bin/sh\ncat <<'EOF'\n" + stdout + "\nEOF\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestScanParsesResults(t *testing.T) {
	stdout := `{
		"results": [
			{
				"check_id": "rules.scryer.java.command-injection",
				"path": "Foo.java",
				"start": {"line": 16, "col": 9},
				"end": {"line": 16, "col": 55},
				"extra": {
					"message": "bad stuff",
					"severity": "ERROR",
					"metadata": {"cwe": "CWE-78", "owasp": ["A03:2021"]}
				}
			}
		],
		"errors": []
	}`
	r := &Runner{BinaryPath: fakeSemgrep(t, stdout, 1)}
	results, err := r.Scan(context.Background(), []string{"rules/"}, ".")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CheckID != "rules.scryer.java.command-injection" {
		t.Errorf("unexpected check_id: %s", results[0].CheckID)
	}
	if len(results[0].Extra.Metadata.CWE) != 1 || results[0].Extra.Metadata.CWE[0] != "CWE-78" {
		t.Errorf("expected CWE string normalized to single-element slice, got %v", results[0].Extra.Metadata.CWE)
	}
	if len(results[0].Extra.Metadata.OWASP) != 1 || results[0].Extra.Metadata.OWASP[0] != "A03:2021" {
		t.Errorf("expected OWASP array to parse as-is, got %v", results[0].Extra.Metadata.OWASP)
	}
}

func TestScanNoFindingsExitZero(t *testing.T) {
	r := &Runner{BinaryPath: fakeSemgrep(t, `{"results": [], "errors": []}`, 0)}
	results, err := r.Scan(context.Background(), []string{"rules/"}, ".")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestScanSurfacesSemgrepErrors(t *testing.T) {
	stdout := `{"results": [], "errors": [{"message": "bad config"}]}`
	r := &Runner{BinaryPath: fakeSemgrep(t, stdout, 0)}
	_, err := r.Scan(context.Background(), []string{"rules/"}, ".")
	if err == nil {
		t.Fatal("expected an error when semgrep reports config errors")
	}
}

func TestScanRequiresAtLeastOneConfig(t *testing.T) {
	r := &Runner{BinaryPath: fakeSemgrep(t, `{"results":[],"errors":[]}`, 0)}
	_, err := r.Scan(context.Background(), nil, ".")
	if err == nil {
		t.Fatal("expected error for empty configs")
	}
}

func TestScanUnparsableOutputWithExecFailure(t *testing.T) {
	r := &Runner{BinaryPath: fakeSemgrep(t, "not json at all", 127)}
	_, err := r.Scan(context.Background(), []string{"rules/"}, ".")
	if err == nil {
		t.Fatal("expected error when semgrep fails and produces no valid JSON")
	}
}

// realSARIFSample is trimmed from an actual `semgrep --sarif` run against
// testdata/fixtures/VulnerableController.java (see docs/FINDINGS.md finding
// #2) - real shape, not guessed. Notably, results[] never carries a "level"
// field directly; severity lives on tool.driver.rules[].defaultConfiguration
// and results reference it only by ruleId.
const realSARIFSample = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Semgrep OSS",
          "rules": [
            {"id": "java.lang.security.audit.formatted-sql-string.formatted-sql-string", "defaultConfiguration": {"level": "warning"}},
            {"id": "rules.scryer.java.command-injection", "defaultConfiguration": {"level": "error"}},
            {"id": "rules.scryer.java.hardcoded-secret", "defaultConfiguration": {"level": "warning"}}
          ]
        }
      },
      "results": [
        {
          "ruleId": "java.lang.security.audit.formatted-sql-string.formatted-sql-string",
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "testdata/fixtures/VulnerableController.java"}, "region": {"startLine": 11}}}]
        },
        {
          "ruleId": "rules.scryer.java.command-injection",
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "testdata/fixtures/VulnerableController.java"}, "region": {"startLine": 16}}}]
        },
        {
          "ruleId": "rules.scryer.java.hardcoded-secret",
          "locations": [{"physicalLocation": {"artifactLocation": {"uri": "testdata/fixtures/VulnerableController.java"}, "region": {"startLine": 20}}}]
        }
      ]
    }
  ]
}`

func TestScanSARIFPassesThroughUnmodified(t *testing.T) {
	r := &Runner{BinaryPath: fakeSemgrep(t, realSARIFSample, 1)}
	out, err := r.ScanSARIF(context.Background(), []string{"rules/"}, ".")
	if err != nil {
		t.Fatalf("ScanSARIF: %v", err)
	}
	// Byte-for-byte (modulo the trailing newline the fake shell script's
	// heredoc adds): this must be exactly what semgrep produced, not a
	// reserialized version that could drop or reorder fields GitHub relies on.
	if strings.TrimRight(string(out), "\n") != realSARIFSample {
		t.Fatalf("expected SARIF output passed through unmodified, got a different byte sequence")
	}
}

func TestScanSARIFRequiresConfig(t *testing.T) {
	r := &Runner{BinaryPath: fakeSemgrep(t, realSARIFSample, 0)}
	if _, err := r.ScanSARIF(context.Background(), nil, "."); err == nil {
		t.Fatal("expected error for empty configs")
	}
}

func TestScanSARIFRejectsInvalidOutput(t *testing.T) {
	r := &Runner{BinaryPath: fakeSemgrep(t, "not sarif at all", 1)}
	if _, err := r.ScanSARIF(context.Background(), []string{"rules/"}, "."); err == nil {
		t.Fatal("expected error when semgrep doesn't produce valid SARIF")
	}
}

// TestSARIFSeverityCounts covers the exact bug found and fixed while
// verifying this feature end-to-end (docs/FINDINGS.md finding #2): real
// semgrep SARIF results omit "level" and rely on the rule's
// defaultConfiguration.level being looked up by ruleId. A version of
// SARIFSeverityCounts that only read results[].level passed this test's
// predecessor (which put level directly on results) but silently counted
// every real finding as "warning" against actual semgrep output.
func TestSARIFSeverityCounts(t *testing.T) {
	counts, err := SARIFSeverityCounts([]byte(realSARIFSample))
	if err != nil {
		t.Fatalf("SARIFSeverityCounts: %v", err)
	}
	if counts["warning"] != 2 {
		t.Errorf("expected 2 warnings (sql-string finding + hardcoded-secret), got %d", counts["warning"])
	}
	if counts["error"] != 1 {
		t.Errorf("expected 1 error (command-injection), got %d", counts["error"])
	}
}

func TestSARIFSeverityCountsDefaultsMissingLevelToWarning(t *testing.T) {
	sarif := `{"runs":[{"results":[{"ruleId":"x"}]}]}`
	counts, err := SARIFSeverityCounts([]byte(sarif))
	if err != nil {
		t.Fatalf("SARIFSeverityCounts: %v", err)
	}
	if counts["warning"] != 1 {
		t.Errorf("expected a result with no level to default to warning per the SARIF spec, got %v", counts)
	}
}
