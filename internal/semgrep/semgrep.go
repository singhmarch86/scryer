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
	if err := requireConfigs(configs); err != nil {
		return nil, err
	}
	stdout, runErr := r.run(ctx, configs, target, "--json")

	var out output
	if jsonErr := json.Unmarshal(stdout, &out); jsonErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("running semgrep: %w", runErr)
		}
		return nil, fmt.Errorf("parsing semgrep output: %w", jsonErr)
	}
	if len(out.Errors) > 0 {
		return nil, fmt.Errorf("semgrep reported %d error(s), first: %s", len(out.Errors), out.Errors[0].Message)
	}

	return out.Results, nil
}

// ScanSARIF runs semgrep with --sarif and returns its output unmodified.
// This deliberately does NOT go through Result/output - GitHub Code
// Scanning consumes Semgrep's own SARIF directly, and round-tripping it
// through Scryer's simplified struct and re-serializing would drop fields
// GitHub relies on (fingerprints for stable finding identity across scans,
// full rule metadata for severity display). Scryer's job here is pure
// plumbing, not reformatting.
func (r *Runner) ScanSARIF(ctx context.Context, configs []string, target string) ([]byte, error) {
	if err := requireConfigs(configs); err != nil {
		return nil, err
	}
	stdout, runErr := r.run(ctx, configs, target, "--sarif")

	// Same "non-zero exit on blocking findings isn't a real error" situation
	// as Scan - confirm stdout is actually valid SARIF rather than trusting
	// the exit code either way.
	var probe struct {
		Version string `json:"version"`
	}
	if jsonErr := json.Unmarshal(stdout, &probe); jsonErr != nil || probe.Version == "" {
		if runErr != nil {
			return nil, fmt.Errorf("running semgrep: %w", runErr)
		}
		return nil, fmt.Errorf("semgrep did not produce valid SARIF output")
	}

	return stdout, nil
}

// SARIFSeverityCounts does a minimal parse of SARIF output — just enough
// to extract result levels for -fail-on gating — without deserializing
// (and risking dropping) anything else. The raw bytes from ScanSARIF are
// what actually gets uploaded/written; this only reads a copy of them.
//
// Real `semgrep --sarif` output (verified against an actual scan, not
// assumed from the SARIF spec) never sets results[].level directly — every
// result omits it and relies on the SARIF-spec fallback: look up the level
// from the matching rule's tool.driver.rules[].defaultConfiguration.level.
// A first version of this function read only results[].level and silently
// counted every real finding as "warning" (the empty-level default),
// breaking -fail-on ERROR gating entirely.
func SARIFSeverityCounts(sarifBytes []byte) (map[string]int, error) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex *int   `json:"ruleIndex"`
				Level     string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifBytes, &doc); err != nil {
		return nil, fmt.Errorf("parsing SARIF for severity counts: %w", err)
	}
	counts := map[string]int{}
	for _, run := range doc.Runs {
		levelByRuleID := make(map[string]string, len(run.Tool.Driver.Rules))
		for _, rule := range run.Tool.Driver.Rules {
			levelByRuleID[rule.ID] = rule.DefaultConfiguration.Level
		}
		rules := run.Tool.Driver.Rules

		for _, res := range run.Results {
			level := res.Level
			if level == "" && res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(rules) {
				level = rules[*res.RuleIndex].DefaultConfiguration.Level
			}
			if level == "" {
				level = levelByRuleID[res.RuleID]
			}
			if level == "" {
				level = "warning" // SARIF's own default when no level is found anywhere
			}
			counts[level]++
		}
	}
	return counts, nil
}

func requireConfigs(configs []string) error {
	if len(configs) == 0 {
		return fmt.Errorf("at least one --config is required")
	}
	return nil
}

// run executes semgrep with the given output-format flag (--json or
// --sarif) plus one --config per entry in configs, and returns raw stdout.
// The returned error wraps stderr for diagnostics; callers decide whether
// a non-zero exit is a real failure or just "there were blocking findings"
// by checking whether stdout itself parses as the expected format.
func (r *Runner) run(ctx context.Context, configs []string, target string, formatFlag string) ([]byte, error) {
	args := []string{formatFlag, "--quiet"}
	for _, c := range configs {
		args = append(args, "--config", c)
	}
	args = append(args, target)

	cmd := exec.CommandContext(ctx, r.BinaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		runErr = fmt.Errorf("%w (stderr: %s)", runErr, stderr.String())
	}
	return stdout.Bytes(), runErr
}
