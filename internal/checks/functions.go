package checks

import (
	"fmt"

	"github.com/Qaid-Danial/rlsprobe/internal/catalog"
)

// RLS005: a view runs with its owner's rights unless security_invoker is set
// (Postgres 15+). If the owner bypasses RLS on the base table, so does
// everyone who can SELECT from the view.
func rls005(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, v := range s.Views {
		if v.SecurityInvoker || len(v.ReadableBy) == 0 || len(v.RLSTables) == 0 {
			continue
		}
		out = append(out, Finding{
			RuleID: "RLS005", Severity: High, Object: v.FullName(),
			Message: fmt.Sprintf("view reads %s as its owner (%s) and %s can select from it, so RLS on those tables may be skipped", list(v.RLSTables), v.Owner, list(v.ReadableBy)),
			Fix:     fmt.Sprintf("ALTER VIEW %s SET (security_invoker = true); (Postgres 15+), or REVOKE SELECT ON %s FROM %s", v.FullName(), v.FullName(), list(v.ReadableBy)),
		})
	}
	return out
}

// RLS006: SECURITY DEFINER runs as the function owner. EXECUTE is granted to
// PUBLIC by default, and in Supabase any function in an exposed schema is
// callable at /rest/v1/rpc/<name>.
func rls006(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, f := range s.Functions {
		if len(f.ExecutableBy) == 0 {
			continue
		}
		out = append(out, Finding{
			RuleID: "RLS006", Severity: Medium, Object: f.Signature,
			Message: fmt.Sprintf("SECURITY DEFINER function is executable by %s and runs with its owner's rights, outside RLS", list(f.ExecutableBy)),
			Fix:     fmt.Sprintf("REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, %s; or move it to a schema the API does not expose, or make it SECURITY INVOKER", f.Signature, list(f.ExecutableBy)),
		})
	}
	return out
}

// RLS009: without a fixed search_path, a caller who can create objects in a
// schema earlier on the path can shadow tables or functions the definer
// function uses, and run code with the owner's rights.
func rls009(s *catalog.Snapshot) []Finding {
	var out []Finding
	for _, f := range s.Functions {
		if f.SearchPathSet {
			continue
		}
		out = append(out, Finding{
			RuleID: "RLS009", Severity: Medium, Object: f.Signature,
			Message: "SECURITY DEFINER function does not set search_path, so name lookups can be hijacked",
			Fix:     fmt.Sprintf("ALTER FUNCTION %s SET search_path = ''; and schema-qualify every name inside it", f.Signature),
		})
	}
	return out
}
