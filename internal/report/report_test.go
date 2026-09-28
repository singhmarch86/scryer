package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/singhmarch86/scryer/internal/semgrep"
)

func TestSortBySeverityOrdersErrorsFirst(t *testing.T) {
	results := []semgrep.Result{
		{Path: "b.java", Extra: semgrep.Extra{Severity: "INFO"}},
		{Path: "a.java", Extra: semgrep.Extra{Severity: "ERROR"}},
		{Path: "c.java", Extra: semgrep.Extra{Severity: "WARNING"}},
	}
	SortBySeverity(results)

	want := []string{"ERROR", "WARNING", "INFO"}
	for i, w := range want {
		if results[i].Extra.Severity != w {
			t.Fatalf("position %d: expected %s, got %s", i, w, results[i].Extra.Severity)
		}
	}
}

func TestSortBySeverityStableWithinSameSeverity(t *testing.T) {
	results := []semgrep.Result{
		{Path: "z.java", Extra: semgrep.Extra{Severity: "ERROR"}},
		{Path: "a.java", Extra: semgrep.Extra{Severity: "ERROR"}},
	}
	SortBySeverity(results)
	if results[0].Path != "a.java" || results[1].Path != "z.java" {
		t.Fatalf("expected alphabetical order within same severity, got %s, %s", results[0].Path, results[1].Path)
	}
}

func TestWriteTextNoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "No findings." {
		t.Fatalf("expected 'No findings.', got %q", buf.String())
	}
}

func TestWriteTextIncludesCountsAndFirstLineOnly(t *testing.T) {
	results := []semgrep.Result{
		{
			CheckID: "rule.one", Path: "Foo.java", Start: semgrep.Pos{Line: 5},
			Extra: semgrep.Extra{Severity: "ERROR", Message: "first line\nsecond line should not appear in the summary"},
		},
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, results); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Foo.java:5") {
		t.Errorf("expected file:line in output, got %q", out)
	}
	if strings.Contains(out, "second line") {
		t.Errorf("expected only the first line of a multi-line message, got %q", out)
	}
	if !strings.Contains(out, "1 finding(s): 1 error, 0 warning, 0 info") {
		t.Errorf("expected severity count summary, got %q", out)
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	results := []semgrep.Result{{CheckID: "rule.one", Path: "Foo.java"}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, results); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"check_id": "rule.one"`) {
		t.Fatalf("expected check_id in JSON output, got %q", buf.String())
	}
}
