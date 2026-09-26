package semgrep

import (
	"context"
	"os"
	"path/filepath"
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
