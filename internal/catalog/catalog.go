package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Load reads the catalog for the given schemas, judging access as the given
// exposed roles. Everything happens inside one READ ONLY transaction, so
// Postgres itself refuses any write, and all queries see one consistent view.
func Load(ctx context.Context, conn *pgx.Conn, schemas, roles []string) (*Snapshot, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("begin read-only transaction: %w", err)
	}
	// Nothing to commit: we only read. Rollback is always safe.
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '30s'"); err != nil {
		return nil, err
	}

	s := &Snapshot{Schemas: schemas}
	if err := tx.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&s.ServerVersion); err != nil {
		return nil, fmt.Errorf("server version: %w", err)
	}

	if s.ExposedRoles, err = loadRoles(ctx, tx, roles); err != nil {
		return nil, fmt.Errorf("roles: %w", err)
	}
	// Privilege functions error on unknown role names, so only pass real ones on.
	var existing []string
	for _, r := range s.ExposedRoles {
		if r.Exists {
			existing = append(existing, r.Name)
		}
	}

	if s.Tables, err = loadTables(ctx, tx, schemas, existing); err != nil {
		return nil, fmt.Errorf("tables: %w", err)
	}
	if s.Policies, err = loadPolicies(ctx, tx, schemas, existing); err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}
	if s.Views, err = loadViews(ctx, tx, schemas, existing); err != nil {
		return nil, fmt.Errorf("views: %w", err)
	}
	if s.Functions, err = loadFunctions(ctx, tx, schemas, existing); err != nil {
		return nil, fmt.Errorf("functions: %w", err)
	}
	return s, nil
}

const rolesSQL = `
SELECT e.name, r.rolname IS NOT NULL, coalesce(r.rolsuper, false), coalesce(r.rolbypassrls, false)
FROM unnest($1::text[]) AS e(name)
LEFT JOIN pg_roles r ON r.rolname = e.name
ORDER BY e.name`

func loadRoles(ctx context.Context, tx pgx.Tx, roles []string) ([]Role, error) {
	rows, err := tx.Query(ctx, rolesSQL, roles)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Role, error) {
		var r Role
		err := row.Scan(&r.Name, &r.Exists, &r.Superuser, &r.BypassRLS)
		return r, err
	})
}

// Ordinary ('r') and partitioned ('p') tables. Partitions themselves are
// skipped: queries through the parent use the parent's policies.
const tablesSQL = `
SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner),
       c.relrowsecurity, c.relforcerowsecurity,
       coalesce(obj_description(c.oid, 'pg_class'), ''),
       array(SELECT a.attname::text FROM pg_attribute a
             WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
             ORDER BY a.attnum)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND n.nspname = ANY($1)
ORDER BY 1, 2`

// has_any_column_privilege is true for a table-level grant OR a grant on any
// single column, so GRANT SELECT (email) ON users TO anon is not missed.
// pg_has_role(..., 'USAGE') is true if the role has the owner's privileges
// through membership, which is the same test Postgres uses to skip RLS.
const accessSQL = `
SELECT n.nspname, c.relname, r.name,
       has_any_column_privilege(r.name, c.oid, 'SELECT'),
       has_any_column_privilege(r.name, c.oid, 'INSERT'),
       has_any_column_privilege(r.name, c.oid, 'UPDATE'),
       has_table_privilege(r.name, c.oid, 'DELETE'),
       pg_has_role(r.name, c.relowner, 'USAGE')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN unnest($2::text[]) AS r(name)
WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND n.nspname = ANY($1)`

func loadTables(ctx context.Context, tx pgx.Tx, schemas, roles []string) ([]Table, error) {
	rows, err := tx.Query(ctx, tablesSQL, schemas)
	if err != nil {
		return nil, err
	}
	tables, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Table, error) {
		t := Table{Access: map[string]Privileges{}}
		err := row.Scan(&t.Schema, &t.Name, &t.Owner, &t.RLSEnabled, &t.RLSForced, &t.Comment, &t.Columns)
		return t, err
	})
	if err != nil {
		return nil, err
	}

	byName := map[string]*Table{}
	for i := range tables {
		byName[tables[i].FullName()] = &tables[i]
	}

	rows, err = tx.Query(ctx, accessSQL, schemas, roles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var schema, name, role string
		var p Privileges
		var owns bool
		if err := rows.Scan(&schema, &name, &role, &p.Select, &p.Insert, &p.Update, &p.Delete, &owns); err != nil {
			return nil, err
		}
		t := byName[schema+"."+name]
		if t == nil {
			continue
		}
		t.Access[role] = p
		if owns {
			t.OwnedBy = append(t.OwnedBy, role)
		}
	}
	return tables, rows.Err()
}

// pg_policy (not the pg_policies view) gives us polroles as OIDs, so we can
// ask Postgres which exposed roles each policy really applies to. OID 0 means
// PUBLIC. Policies apply to members of the named role, hence 'MEMBER'.
const policiesSQL = `
SELECT n.nspname, c.relname, p.polname, p.polcmd::text, p.polpermissive,
       array(SELECT CASE WHEN r = 0 THEN 'public' ELSE pg_get_userbyid(r) END
             FROM unnest(p.polroles) AS r),
       array(SELECT e FROM unnest($2::text[]) AS e
             WHERE 0 = ANY(p.polroles)
                OR EXISTS (SELECT 1 FROM unnest(p.polroles) AS r
                           WHERE r <> 0 AND pg_has_role(e, r, 'MEMBER'))),
       coalesce(pg_get_expr(p.polqual, p.polrelid), ''),
       coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
FROM pg_policy p
JOIN pg_class c ON c.oid = p.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = ANY($1)
ORDER BY 1, 2, 3`

var commands = map[string]string{"*": "ALL", "r": "SELECT", "a": "INSERT", "w": "UPDATE", "d": "DELETE"}

func loadPolicies(ctx context.Context, tx pgx.Tx, schemas, roles []string) ([]Policy, error) {
	rows, err := tx.Query(ctx, policiesSQL, schemas, roles)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Policy, error) {
		var p Policy
		var cmd string
		err := row.Scan(&p.Schema, &p.Table, &p.Name, &cmd, &p.Permissive, &p.Roles, &p.AppliesTo, &p.Using, &p.WithCheck)
		p.Command = commands[cmd]
		return p, err
	})
}

// A view's rewrite rule depends on every relation the view reads directly.
const viewsSQL = `
SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner),
       coalesce(c.reloptions, '{}'),
       array(SELECT e FROM unnest($2::text[]) AS e
             WHERE has_table_privilege(e, c.oid, 'SELECT')),
       array(SELECT DISTINCT dn.nspname || '.' || dc.relname
             FROM pg_rewrite rw
             JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid
                             AND d.refclassid = 'pg_class'::regclass
             JOIN pg_class dc ON dc.oid = d.refobjid
             JOIN pg_namespace dn ON dn.oid = dc.relnamespace
             WHERE rw.ev_class = c.oid AND dc.oid <> c.oid AND dc.relrowsecurity),
       coalesce(obj_description(c.oid, 'pg_class'), '')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'v' AND n.nspname = ANY($1)
ORDER BY 1, 2`

func loadViews(ctx context.Context, tx pgx.Tx, schemas, roles []string) ([]View, error) {
	rows, err := tx.Query(ctx, viewsSQL, schemas, roles)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (View, error) {
		var v View
		var opts []string
		err := row.Scan(&v.Schema, &v.Name, &v.Owner, &opts, &v.ReadableBy, &v.RLSTables, &v.Comment)
		v.SecurityInvoker = optionTrue(opts, "security_invoker")
		return v, err
	})
}

// optionTrue reads a boolean reloption such as "security_invoker=true".
// Postgres stores the value as written, so accept every boolean spelling.
func optionTrue(opts []string, key string) bool {
	for _, o := range opts {
		k, v, _ := strings.Cut(o, "=")
		if k == key {
			switch strings.ToLower(v) {
			case "true", "on", "yes", "1", "t", "y":
				return true
			}
		}
	}
	return false
}

// SECURITY DEFINER functions and procedures, excluding ones that belong to an
// extension (those are the extension author's problem, not the app's).
const functionsSQL = `
SELECT format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
       EXISTS (SELECT 1 FROM unnest(p.proconfig) AS cfg WHERE cfg LIKE 'search_path=%'),
       array(SELECT e FROM unnest($2::text[]) AS e
             WHERE has_function_privilege(e, p.oid, 'EXECUTE')),
       coalesce(obj_description(p.oid, 'pg_proc'), '')
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname = ANY($1)
  AND NOT EXISTS (SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
ORDER BY 1`

func loadFunctions(ctx context.Context, tx pgx.Tx, schemas, roles []string) ([]Function, error) {
	rows, err := tx.Query(ctx, functionsSQL, schemas, roles)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Function, error) {
		var f Function
		err := row.Scan(&f.Signature, &f.SearchPathSet, &f.ExecutableBy, &f.Comment)
		return f, err
	})
}
