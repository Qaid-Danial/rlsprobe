// Package report renders findings for people (table) and machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Qaid-Danial/rlsprobe/internal/checks"
)

// Renderer writes findings somewhere. SARIF (v3) will be a third one.
type Renderer interface {
	Render(w io.Writer, findings []checks.Finding) error
}

// For returns the renderer for a --format value.
func For(format string) (Renderer, error) {
	switch format {
	case "table":
		return Table{}, nil
	case "json":
		return JSON{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (want table or json)", format)
}

type Table struct{}

func (Table) Render(w io.Writer, findings []checks.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	for _, f := range findings {
		subject := f.Object
		if f.Policy != "" {
			subject += fmt.Sprintf(" policy %q", f.Policy)
		}
		if _, err := fmt.Fprintf(w, "%-8s %s  %s\n         %s\n         fix: %s\n\n",
			strings.ToUpper(f.Severity.String()), f.RuleID, subject, f.Message, f.Fix); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, summary(findings))
	return err
}

func summary(findings []checks.Finding) string {
	counts := map[checks.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for s := checks.Critical; s >= checks.Info; s-- {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return fmt.Sprintf("%d findings: %s", len(findings), strings.Join(parts, ", "))
}

type JSON struct{}

func (JSON) Render(w io.Writer, findings []checks.Finding) error {
	if findings == nil {
		findings = []checks.Finding{} // print [] rather than null
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Findings []checks.Finding `json:"findings"`
	}{findings})
}

// Failed reports whether any finding is at or above the --fail-on threshold.
func Failed(findings []checks.Finding, threshold checks.Severity) bool {
	for _, f := range findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}
