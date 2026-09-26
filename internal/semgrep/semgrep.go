// Package semgrep shells out to the semgrep CLI and parses its JSON
// output. It does not reimplement any detection logic — Semgrep itself
// (and the rule packs it's pointed at) is the engine; this package is
// just the plumbing to run it and get structured results back.
package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Result is one finding, as reported by `semgrep --json`.
type Result struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   Pos    `json:"start"`
	End     Pos    `json:"end"`
	Extra   Extra  `json:"extra"`
}

type Pos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type Extra struct {
	Message  string   `json:"message"`
	Severity string   `json:"severity"` // "ERROR", "WARNING", "INFO"
	Metadata Metadata `json:"metadata"`
}

type Metadata struct {
	// CWE and OWASP are StringOrSlice because official Semgrep registry
	// rules report these as a JSON array (a rule can map to multiple
	// CWEs/OWASP categories), while it's natural to write a single string
	// in a hand-written custom rule (as Scryer's own rules do) — found by
	// actually running scryer against p/java, not by reading a schema doc.
	CWE        StringOrSlice `json:"cwe,omitempty"`
	OWASP      StringOrSlice `json:"owasp,omitempty"`
	References []string      `json:"references,omitempty"`
}

// StringOrSlice unmarshals a JSON value that's either a single string or
// an array of strings into a []string, normalizing both shapes.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = StringOrSlice{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*s = StringOrSlice(multi)
	return nil
}

// output mirrors the top-level shape of `semgrep --json`; we only decode
// the fields Scryer currently uses.
type output struct {
	Results []Result `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// Runner invokes semgrep as a subprocess.
type Runner struct {
	// BinaryPath is the semgrep executable to run. Empty means "semgrep"
	// resolved via $PATH.
	BinaryPath string
}

func NewRunner() *Runner {
	return &Runner{BinaryPath: "semgrep"}
}

// Scan runs semgrep with the given rule configs (each passed as its own
// --config, matching semgrep's own semantics for combining multiple rule
// sources) against target, and returns the parsed findings.
func (r *Runner) Scan(ctx context.Context, configs []string, target string) ([]Result, error) {
	if len(configs) == 0 {
		return nil, fmt.Errorf("at least one --config is required")
	}

	args := []string{"--json", "--quiet"}
	for _, c := range configs {
		args = append(args, "--config", c)
	}
	args = append(args, target)

	cmd := exec.CommandContext(ctx, r.BinaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Semgrep exits non-zero when it finds blocking results, which is not
	// an error from Scryer's point of view - only a genuine execution
	// failure (bad config, semgrep not installed, etc.) is. Distinguish by
	// whether stdout parses as valid semgrep JSON.
	runErr := cmd.Run()

	var out output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("running semgrep: %w (stderr: %s)", runErr, stderr.String())
		}
		return nil, fmt.Errorf("parsing semgrep output: %w", err)
	}
	if len(out.Errors) > 0 {
		return nil, fmt.Errorf("semgrep reported %d error(s), first: %s", len(out.Errors), out.Errors[0].Message)
	}

	return out.Results, nil
}
