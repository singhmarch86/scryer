// Package report formats semgrep.Result findings for humans and for CI.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/gauravdeepsingh/scryer/internal/semgrep"
)

var severityRank = map[string]int{"ERROR": 0, "WARNING": 1, "INFO": 2}

// SortBySeverity orders findings ERROR, then WARNING, then INFO, and by
// file path within each severity - so the most actionable findings surface
// first regardless of scan order.
func SortBySeverity(results []semgrep.Result) {
	sort.SliceStable(results, func(i, j int) bool {
		si, sj := severityRank[results[i].Extra.Severity], severityRank[results[j].Extra.Severity]
		if si != sj {
			return si < sj
		}
		return results[i].Path < results[j].Path
	})
}

// WriteText writes a human-readable summary: one line per finding, grouped
// implicitly by the SortBySeverity ordering, plus a severity-count summary.
func WriteText(w io.Writer, results []semgrep.Result) error {
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Extra.Severity]++
	}

	if len(results) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}

	for _, r := range results {
		if _, err := fmt.Fprintf(w, "[%s] %s:%d %s\n    %s\n\n",
			r.Extra.Severity, r.Path, r.Start.Line, r.CheckID, firstLine(r.Extra.Message)); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, "%d finding(s): %d error, %d warning, %d info\n",
		len(results), counts["ERROR"], counts["WARNING"], counts["INFO"])
	return err
}

// WriteJSON writes findings as a JSON array, for scripting/CI consumption
// that doesn't need full SARIF.
func WriteJSON(w io.Writer, results []semgrep.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}
