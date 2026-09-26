// Command scryer runs Semgrep (official rule packs plus Scryer's own
// Spring-specific custom rules) against a Java/Spring codebase and reports
// findings.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gauravdeepsingh/scryer/internal/report"
	"github.com/gauravdeepsingh/scryer/internal/semgrep"
)

func main() {
	os.Exit(run())
}

func run() int {
	target := flag.String("target", ".", "path to the codebase to scan")
	// p/security-audit and p/owasp-top-ten carry the taint-mode SpEL/JPA
	// injection, CSRF, XXE, and deserialization coverage this tool's own
	// README describes — p/java alone doesn't include them (verified
	// against testdata/fixtures/spring, see docs/FINDINGS.md #3). rules/ is
	// Scryer's own pack, which currently adds only permissive-CORS: the one
	// class of the original Phase 2 scope not already covered by the free
	// registry.
	configsFlag := flag.String("config", "p/java,p/security-audit,p/owasp-top-ten,rules/", "comma-separated semgrep --config values (registry names like p/java, or local paths)")
	format := flag.String("format", "text", "output format: text, json, or sarif (for GitHub Code Scanning upload)")
	failOn := flag.String("fail-on", "ERROR", "exit non-zero if any finding at or above this severity is present: ERROR, WARNING, INFO, or none")
	flag.Parse()

	configs := strings.Split(*configsFlag, ",")
	runner := semgrep.NewRunner()

	if *format == "sarif" {
		return runSARIF(runner, configs, *target, *failOn)
	}

	results, err := runner.Scan(context.Background(), configs, *target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scryer:", err)
		return 2
	}

	report.SortBySeverity(results)

	switch *format {
	case "json":
		if err := report.WriteJSON(os.Stdout, results); err != nil {
			fmt.Fprintln(os.Stderr, "scryer:", err)
			return 2
		}
	default:
		if err := report.WriteText(os.Stdout, results); err != nil {
			fmt.Fprintln(os.Stderr, "scryer:", err)
			return 2
		}
	}

	if shouldFail(results, *failOn) {
		return 1
	}
	return 0
}

func shouldFail(results []semgrep.Result, failOn string) bool {
	threshold, ok := map[string]int{"ERROR": 0, "WARNING": 1, "INFO": 2}[strings.ToUpper(failOn)]
	if !ok {
		return false // "none" or unrecognized: never fail the exit code on findings
	}
	rank := map[string]int{"ERROR": 0, "WARNING": 1, "INFO": 2}
	for _, r := range results {
		if rank[r.Extra.Severity] <= threshold {
			return true
		}
	}
	return false
}

// runSARIF writes semgrep's native SARIF straight to stdout for upload to
// GitHub Code Scanning. It's a separate path from the text/json case in run()
// because -fail-on gating on SARIF's own level naming (lowercase
// error/warning/note) differs from the ERROR/WARNING/INFO scheme
// semgrep.Result uses, and there's no []semgrep.Result here to sort or
// reformat — the SARIF bytes are passed through unmodified.
func runSARIF(runner *semgrep.Runner, configs []string, target, failOn string) int {
	sarifBytes, err := runner.ScanSARIF(context.Background(), configs, target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scryer:", err)
		return 2
	}
	if _, err := os.Stdout.Write(sarifBytes); err != nil {
		fmt.Fprintln(os.Stderr, "scryer:", err)
		return 2
	}

	counts, err := semgrep.SARIFSeverityCounts(sarifBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scryer:", err)
		return 2
	}
	if shouldFailSARIF(counts, failOn) {
		return 1
	}
	return 0
}

// shouldFailSARIF mirrors shouldFail's threshold logic but against SARIF's
// lowercase error/warning/note levels instead of Result's uppercase
// ERROR/WARNING/INFO severities.
func shouldFailSARIF(counts map[string]int, failOn string) bool {
	rank := map[string]int{"error": 0, "warning": 1, "note": 2}
	// Accept the ERROR/WARNING/INFO spelling used by -fail-on's own flag
	// description too, since SARIF's "note" is semgrep's INFO under a
	// different name (verified against a real `semgrep --sarif` run).
	aliases := map[string]string{"info": "note"}
	key := strings.ToLower(failOn)
	if alias, ok := aliases[key]; ok {
		key = alias
	}
	threshold, ok := rank[key]
	if !ok {
		return false
	}
	for level, n := range counts {
		if n == 0 {
			continue
		}
		if r, known := rank[level]; known && r <= threshold {
			return true
		}
	}
	return false
}
