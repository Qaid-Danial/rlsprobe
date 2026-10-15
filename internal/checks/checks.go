// Package checks turns a catalog.Snapshot into findings.
// Every rule is a pure function: same snapshot in, same findings out.
package checks

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/Qaid-Danial/rlsprobe/internal/catalog"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string { return severityNames[s] }

// MarshalText makes JSON output say "high" instead of 3.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity turns a --fail-on value into a Severity.
func ParseSeverity(s string) (Severity, error) {
	for i, name := range severityNames {
		if strings.EqualFold(s, name) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of %s)", s, strings.Join(severityNames, ", "))
}

// Finding is one problem on one object.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Object   string   `json:"object"`           // schema.table, schema.view or schema.func(args)
	Policy   string   `json:"policy,omitempty"` // set when the finding is about one policy
	Message  string   `json:"message"`
	Fix      string   `json:"fix"`
}

// Rule is one check. Tag is "core" (any Postgres) or "supabase".
type Rule struct {
	ID    string
	Title string
	Tag   string
	Check func(*catalog.Snapshot) []Finding
}

// Rules is the registry, in ID order. Adding a rule = adding one line here.
var Rules = []Rule{
	{"RLS001", "RLS disabled on an exposed table", "core", rls001},
	{"RLS002", "Policy allows every row", "core", rls002},
	{"RLS003", "Write policy does not pin the owner column", "core", rls003},
	{"RLS004", "Policy trusts user_metadata from the JWT", "supabase", rls004},
	{"RLS005", "View bypasses RLS of the tables it reads", "core", rls005},
	{"RLS006", "SECURITY DEFINER function callable by exposed roles", "core", rls006},
	{"RLS007", "RLS enabled but no policies", "core", rls007},
	{"RLS008", "RLS not forced for the table owner", "core", rls008},
	{"RLS009", "SECURITY DEFINER function without a fixed search_path", "core", rls009},
	{"RLS010", "Exposed role bypasses RLS entirely", "core", rls010},
	{"RLS011", "Exposed role owns the table and RLS is not forced", "core", rls011},
}

// Run runs every rule that applies to the profile, drops findings the
// database has marked as ignored, and returns the rest sorted worst first.
func Run(s *catalog.Snapshot, profile string) []Finding {
	ignored := ignoreList(s)
	var out []Finding
	for _, r := range Rules {
		if r.Tag == "supabase" && profile != "supabase" {
			continue
		}
		for _, f := range r.Check(s) {
			if !ignored[f.Object][f.RuleID] {
				out = append(out, f)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity), // worst first
			cmp.Compare(a.RuleID, b.RuleID),
			cmp.Compare(a.Object, b.Object),
			cmp.Compare(a.Policy, b.Policy),
		)
	})
	return out
}

// Annotations live in COMMENT ON, e.g.
//
//	COMMENT ON TABLE public.posts IS 'Public feed. rlsprobe:ignore=RLS002 rlsprobe:owner=author_id';
//
// annotation returns the value of one key, or "".
func annotation(comment, key string) string {
	for _, word := range strings.Fields(comment) {
		if v, ok := strings.CutPrefix(word, "rlsprobe:"+key+"="); ok {
			return v
		}
	}
	return ""
}

func ignoreList(s *catalog.Snapshot) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(object, comment string) {
		for _, id := range strings.Split(annotation(comment, "ignore"), ",") {
			if id == "" {
				continue
			}
			if out[object] == nil {
				out[object] = map[string]bool{}
			}
			out[object][strings.ToUpper(id)] = true
		}
	}
	for _, t := range s.Tables {
		add(t.FullName(), t.Comment)
	}
	for _, v := range s.Views {
		add(v.FullName(), v.Comment)
	}
	for _, f := range s.Functions {
		add(f.Signature, f.Comment)
	}
	return out
}

// rolesWith returns the exposed roles whose privileges match want, sorted.
func rolesWith(t catalog.Table, want func(catalog.Privileges) bool) []string {
	var out []string
	for role, p := range t.Access {
		if want(p) {
			out = append(out, role)
		}
	}
	slices.Sort(out)
	return out
}

func list(roles []string) string { return strings.Join(roles, ", ") }
