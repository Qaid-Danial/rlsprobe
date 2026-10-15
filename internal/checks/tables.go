package checks

import (
	"fmt"
	"slices"

	"github.com/Qaid-Danial/rlsprobe/internal/catalog"
)

// RLS001: without RLS, table privileges are the only gate. In Supabase the
// anon key holder has those privileges, so every row is readable/writable.
func rls001(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, t := range s.Tables {
		if t.RLSEnabled {
			continue
		}
		roles := rolesWith(t, catalog.Privileges.Any)
		if len(roles) == 0 {
			continue
		}
		out = append(out, Finding{
			RuleID: "RLS001", Severity: Critical, Object: t.FullName(),
			Message: fmt.Sprintf("RLS is disabled and %s can access the table, so every row is exposed", list(roles)),
			Fix:     fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY; then add policies (or REVOKE ALL ON %s FROM %s)", t.FullName(), t.FullName(), list(roles)),
		})
	}
	return out
}

// RLS007: RLS on with zero policies means default deny for everyone except
// the owner and BYPASSRLS roles. Safe, but almost always a forgotten policy.
func rls007(s *catalog.Snapshot) []Finding {
	hasPolicy := map[string]bool{}
	for _, p := range s.Policies {
		hasPolicy[p.TableName()] = true
	}
	var out []Finding
	for _, t := range s.Tables {
		if t.RLSEnabled && !hasPolicy[t.FullName()] {
			out = append(out, Finding{
				RuleID: "RLS007", Severity: Low, Object: t.FullName(),
				Message: "RLS is enabled but there are no policies, so exposed roles see no rows",
				Fix:     "add the policies you intended, or REVOKE the table from exposed roles if it is internal",
			})
		}
	}
	return out
}

// owners returns the exposed, non-superuser roles that own t. Superusers
// "own" everything and are already reported by RLS010.
func owners(s *catalog.Snapshot, t catalog.Table) []string {
	var out []string
	for _, name := range t.OwnedBy {
		i := slices.IndexFunc(s.ExposedRoles, func(r catalog.Role) bool { return r.Name == name })
		if i >= 0 && !s.ExposedRoles[i].Superuser {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// RLS008: the owner skips RLS unless FORCE is set. Informational when the
// app does not connect as the owner; RLS011 covers the case where it does.
func rls008(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, t := range s.Tables {
		if t.RLSEnabled && !t.RLSForced && len(owners(s, t)) == 0 {
			out = append(out, Finding{
				RuleID: "RLS008", Severity: Info, Object: t.FullName(),
				Message: fmt.Sprintf("RLS is not forced, so the owner (%s) bypasses every policy", t.Owner),
				Fix:     fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY;", t.FullName()),
			})
		}
	}
	return out
}

// RLS011: the app connects as (or inherits) the owner, so policies are
// silently skipped for every request.
func rls011(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, t := range s.Tables {
		o := owners(s, t)
		if t.RLSEnabled && !t.RLSForced && len(o) > 0 {
			out = append(out, Finding{
				RuleID: "RLS011", Severity: Critical, Object: t.FullName(),
				Message: fmt.Sprintf("%s owns the table (owner: %s) and RLS is not forced, so every policy is ignored for it", list(o), t.Owner),
				Fix:     fmt.Sprintf("move ownership to a separate role (ALTER TABLE %s OWNER TO ...); at minimum ALTER TABLE %s FORCE ROW LEVEL SECURITY. An owner can always disable RLS again, so ownership is the real fix", t.FullName(), t.FullName()),
			})
		}
	}
	return out
}

// RLS010: superuser and BYPASSRLS skip RLS on every table, FORCE or not.
func rls010(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, r := range s.ExposedRoles {
		var why string
		switch {
		case r.Superuser:
			why = "is a superuser"
		case r.BypassRLS:
			why = "has BYPASSRLS"
		default:
			continue
		}
		out = append(out, Finding{
			RuleID: "RLS010", Severity: Critical, Object: "role " + r.Name,
			Message: fmt.Sprintf("exposed role %s %s, so RLS never applies to it", r.Name, why),
			Fix:     fmt.Sprintf("ALTER ROLE %s NOSUPERUSER NOBYPASSRLS; and connect the app as a dedicated least-privilege role", r.Name),
		})
	}
	return out
}
