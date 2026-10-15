// Package catalog reads the Postgres system catalog into a Snapshot.
// It is the only package in rlsprobe that talks to a database.
package catalog

// Snapshot is everything the checks need, captured once.
// It holds no table data, only metadata about tables, policies and roles.
type Snapshot struct {
	ServerVersion int        `json:"server_version"` // e.g. 160004 for 16.4
	Schemas       []string   `json:"schemas"`
	ExposedRoles  []Role     `json:"exposed_roles"`
	Tables        []Table    `json:"tables"`
	Policies      []Policy   `json:"policies"`
	Views         []View     `json:"views"`
	Functions     []Function `json:"functions"`
}

// Role is one of the roles an attacker can act as (anon, authenticated, app_user...).
type Role struct {
	Name      string `json:"name"`
	Exists    bool   `json:"exists"`
	Superuser bool   `json:"superuser"`
	BypassRLS bool   `json:"bypass_rls"`
}

// Privileges says what one role may do to one table.
type Privileges struct {
	Select bool `json:"select"`
	Insert bool `json:"insert"`
	Update bool `json:"update"`
	Delete bool `json:"delete"`
}

// Any reports whether the role can touch the table at all.
func (p Privileges) Any() bool { return p.Select || p.Insert || p.Update || p.Delete }

type Table struct {
	Schema     string                `json:"schema"`
	Name       string                `json:"name"`
	Owner      string                `json:"owner"`
	RLSEnabled bool                  `json:"rls_enabled"`
	RLSForced  bool                  `json:"rls_forced"`
	Columns    []string              `json:"columns"`
	Comment    string                `json:"comment,omitempty"`
	Access     map[string]Privileges `json:"access"`   // exposed role -> privileges
	OwnedBy    []string              `json:"owned_by"` // exposed roles that own it, directly or via membership
}

// FullName returns schema.name, the key used for findings and ignore comments.
func (t Table) FullName() string { return t.Schema + "." + t.Name }

type Policy struct {
	Schema     string   `json:"schema"`
	Table      string   `json:"table"`
	Name       string   `json:"name"`
	Command    string   `json:"command"` // ALL, SELECT, INSERT, UPDATE, DELETE
	Permissive bool     `json:"permissive"`
	Roles      []string `json:"roles"`      // as written in CREATE POLICY ... TO
	AppliesTo  []string `json:"applies_to"` // exposed roles this policy actually applies to
	Using      string   `json:"using,omitempty"`
	WithCheck  string   `json:"with_check,omitempty"`
}

func (p Policy) TableName() string { return p.Schema + "." + p.Table }

type View struct {
	Schema          string   `json:"schema"`
	Name            string   `json:"name"`
	Owner           string   `json:"owner"`
	SecurityInvoker bool     `json:"security_invoker"`
	ReadableBy      []string `json:"readable_by"`
	RLSTables       []string `json:"rls_tables"` // RLS-enabled tables the view reads directly
	Comment         string   `json:"comment,omitempty"`
}

func (v View) FullName() string { return v.Schema + "." + v.Name }

// Function is a SECURITY DEFINER function. Normal functions are not captured.
type Function struct {
	Signature     string   `json:"signature"` // schema.name(args), e.g. public.f(target uuid)
	SearchPathSet bool     `json:"search_path_set"`
	ExecutableBy  []string `json:"executable_by"`
	Comment       string   `json:"comment,omitempty"`
}
