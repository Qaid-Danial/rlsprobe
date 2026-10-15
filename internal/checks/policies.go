package checks

import (
	"fmt"
	"slices"

	"github.com/Qaid-Danial/rlsprobe/internal/catalog"
	"github.com/Qaid-Danial/rlsprobe/internal/policy"
)

// parse parses one policy clause. Empty clauses return nil. If the parser
// fails, we say so as an Info finding instead of guessing: a silent skip
// would look exactly like "no problem found".
func parse(rule string, p catalog.Policy, clause, text string, out *[]Finding) *policy.Expr {
	if text == "" {
		return nil
	}
	e, err := policy.Parse(text)
	if err != nil {
		*out = append(*out, Finding{
			RuleID: rule, Severity: Info, Object: p.TableName(), Policy: p.Name,
			Message: fmt.Sprintf("could not parse %s clause, review it by hand: %v", clause, err),
			Fix:     "report this expression as an rlsprobe bug",
		})
	}
	return e
}

// RLS002: USING (true) / WITH CHECK (true) on a permissive policy means the
// policy grants every row to the roles it names. Sometimes intended (a public
// feed); mark those with rlsprobe:ignore=RLS002.
func rls002(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, p := range s.Policies {
		if !p.Permissive || len(p.AppliesTo) == 0 {
			continue
		}
		for _, c := range []struct{ name, text string }{{"USING", p.Using}, {"WITH CHECK", p.WithCheck}} {
			e := parse("RLS002", p, c.name, c.text, &out)
			if e == nil || !e.IsTrue() {
				continue
			}
			out = append(out, Finding{
				RuleID: "RLS002", Severity: High, Object: p.TableName(), Policy: p.Name,
				Message: fmt.Sprintf("%s policy %q has %s (true): %s can %s every row", p.Command, p.Name, c.name, list(p.AppliesTo), verb(p.Command, c.name)),
				Fix:     fmt.Sprintf("restrict the expression (e.g. (select auth.uid()) = user_id); if the table is public on purpose: COMMENT ON TABLE %s IS 'rlsprobe:ignore=RLS002'", p.TableName()),
			})
		}
	}
	return out
}

func verb(cmd, clause string) string {
	if clause == "WITH CHECK" {
		return "write"
	}
	if cmd == "ALL" {
		return "read and change"
	}
	return map[string]string{"SELECT": "read", "UPDATE": "update", "DELETE": "delete"}[cmd]
}

// RLS004: user_metadata is writable by the user themselves
// (supabase.auth.updateUser({ data: {...} })), so a policy that trusts it
// lets users grant themselves access. app_metadata is server-only.
func rls004(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, p := range s.Policies {
		for _, text := range []string{p.Using, p.WithCheck} {
			e := parse("RLS004", p, "policy", text, &out)
			if e != nil && e.ReadsJWTKey("user_metadata") {
				out = append(out, Finding{
					RuleID: "RLS004", Severity: High, Object: p.TableName(), Policy: p.Name,
					Message: fmt.Sprintf("policy %q reads user_metadata from the JWT, which users can edit themselves", p.Name),
					Fix:     "use app_metadata (only the service role can set it) or a roles table users cannot write",
				})
				break // one finding per policy, even if both clauses use it
			}
		}
	}
	return out
}

// ownerHeuristics are tried, in order, when no policy tells us the owner column.
var ownerHeuristics = []string{"user_id", "owner_id", "author_id", "created_by", "profile_id", "tenant_id", "org_id", "team_id"}

// ownerColumns decides which columns say who owns a row of t:
//  1. an explicit rlsprobe:owner=<col> annotation,
//  2. columns that any policy's USING clause ties to the current user,
//  3. the first heuristic name the table actually has.
func ownerColumns(t catalog.Table, policies []catalog.Policy) []string {
	if col := annotation(t.Comment, "owner"); col != "" {
		return []string{col}
	}
	var cols []string
	for _, p := range policies {
		if p.Using == "" {
			continue
		}
		if e, err := policy.Parse(p.Using); err == nil {
			for _, c := range e.PinnedColumns(t.Name) {
				if !slices.Contains(cols, c) {
					cols = append(cols, c)
				}
			}
		}
	}
	if len(cols) > 0 {
		return cols
	}
	for _, h := range ownerHeuristics {
		if slices.Contains(t.Columns, h) {
			return []string{h}
		}
	}
	return nil
}

// writeCheck is the expression Postgres checks new rows against: WITH CHECK
// if present, otherwise USING (UPDATE and ALL reuse it for new rows).
func writeCheck(p catalog.Policy) string {
	if p.WithCheck != "" || p.Command == "INSERT" {
		return p.WithCheck
	}
	return p.Using
}

func appliesToWrite(cmd, want string) bool { return cmd == "ALL" || cmd == want }

// RLS003: a write policy whose check does not pin the owner column lets a
// user insert rows as someone else, or UPDATE their own row to hand it to
// another user. Permissive policies are OR'ed together, restrictive ones
// AND'ed, so a restrictive policy that pins the owner makes the table safe.
func rls003(s *catalog.Snapshot) []Finding {
	byTable := map[string][]catalog.Policy{}
	for _, p := range s.Policies {
		byTable[p.TableName()] = append(byTable[p.TableName()], p)
	}

	var out []Finding
	for _, t := range s.Tables {
		policies := byTable[t.FullName()]
		cols := ownerColumns(t, policies)
		if len(cols) == 0 {
			continue // we cannot judge a table with no detectable owner
		}
		pins := func(text string) bool {
			if text == "" {
				return false
			}
			e, err := policy.Parse(text)
			if err != nil {
				return false
			}
			return slices.ContainsFunc(cols, func(c string) bool { return e.Pins(t.Name, c) })
		}

		for _, p := range policies {
			if !p.Permissive || len(p.AppliesTo) == 0 || !slices.Contains([]string{"INSERT", "UPDATE", "ALL"}, p.Command) {
				continue
			}
			check := writeCheck(p)
			if check == "" {
				continue // INSERT with no WITH CHECK admits no rows at all (verified on PG 16)
			}
			if e, err := policy.Parse(check); err == nil && e.IsTrue() {
				continue // RLS002 already reports (true)
			}
			if pins(check) {
				continue
			}
			restricted := slices.ContainsFunc(policies, func(r catalog.Policy) bool {
				return !r.Permissive && appliesToWrite(r.Command, p.Command) && pins(writeCheck(r))
			})
			if restricted {
				continue
			}
			out = append(out, Finding{
				RuleID: "RLS003", Severity: High, Object: t.FullName(), Policy: p.Name,
				Message: fmt.Sprintf("%s policy %q does not pin %s in its write check, so %s can write rows owned by someone else", p.Command, p.Name, list(cols), list(p.AppliesTo)),
				Fix:     fmt.Sprintf("add WITH CHECK ((select auth.uid()) = %s) (or your tenant check); if the owner column is different: COMMENT ON TABLE %s IS 'rlsprobe:owner=<column>'", cols[0], t.FullName()),
			})
		}
	}
	return out
}
