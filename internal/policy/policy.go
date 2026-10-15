// Package policy parses RLS policy expressions with the real Postgres parser
// (libpg_query, via pg_query_go) and answers questions about them.
package policy

import (
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Expr is a parsed policy expression such as "(auth.uid() = user_id)".
type Expr struct {
	root *pg_query.Node
}

// Parse parses the text that pg_get_expr returned for a USING or WITH CHECK
// clause. The parser only accepts whole statements, so we wrap the expression
// in "SELECT 1 WHERE <expr>" and take the WHERE clause back out.
func Parse(expr string) (*Expr, error) {
	tree, err := pg_query.Parse("SELECT 1 WHERE " + expr)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", expr, err)
	}
	stmts := tree.GetStmts()
	if len(stmts) != 1 {
		return nil, fmt.Errorf("parse %q: expected one statement", expr)
	}
	sel := stmts[0].GetStmt().GetSelectStmt()
	if sel == nil || sel.GetWhereClause() == nil {
		return nil, fmt.Errorf("parse %q: no expression found", expr)
	}
	return &Expr{root: sel.GetWhereClause()}, nil
}

// IsTrue reports whether the expression is the constant true, which is how
// USING (true) comes back (sometimes wrapped in a cast).
func (e *Expr) IsTrue() bool {
	n := unwrapCast(e.root)
	if c := n.GetAConst(); c != nil {
		return c.GetBoolval() != nil && c.GetBoolval().GetBoolval()
	}
	return false
}

// ReadsJWTKey reports whether the expression reads a top-level key of
// auth.jwt(), for example auth.jwt() -> 'user_metadata'.
func (e *Expr) ReadsJWTKey(key string) bool {
	found := false
	walk(e.root, func(n *pg_query.Node) {
		a := n.GetAExpr()
		if a == nil || !isJSONOperator(opName(a)) {
			return
		}
		if isFunc(unwrapCast(a.GetLexpr()), "auth", "jwt") && stringConst(a.GetRexpr()) == key {
			found = true
		}
	})
	return found
}

// PinnedColumns returns the columns the expression ties to the current user.
// Only top-level AND branches count: in "a OR b" neither side is guaranteed.
// A column is pinned by one of these patterns:
//
//	col = auth.uid()                     (either side; any identity expression)
//	col IN (SELECT ... auth.uid() ...)   (membership tables)
//	EXISTS (SELECT ... table.col ... auth.uid() ...)
//	some_helper(col)                     (trusted: we cannot see inside it)
//
// table is the policy's table name, used to spot outer references in EXISTS.
func (e *Expr) PinnedColumns(table string) []string {
	var cols []string
	for _, c := range conjuncts(e.root) {
		cols = append(cols, pinnedBy(c, table)...)
	}
	return cols
}

// Pins reports whether col is one of the pinned columns.
func (e *Expr) Pins(table, col string) bool {
	for _, c := range e.PinnedColumns(table) {
		if c == col {
			return true
		}
	}
	return false
}

func pinnedBy(n *pg_query.Node, table string) []string {
	switch {
	case n.GetAExpr() != nil:
		a := n.GetAExpr()
		if opName(a) != "=" {
			return nil
		}
		l, r := unwrapCast(a.GetLexpr()), unwrapCast(a.GetRexpr())
		if col := columnName(l); col != "" && hasIdentity(r) {
			return []string{col}
		}
		if col := columnName(r); col != "" && hasIdentity(l) {
			return []string{col}
		}
	case n.GetSubLink() != nil:
		s := n.GetSubLink()
		if !hasIdentity(s.GetSubselect()) {
			return nil
		}
		switch s.GetSubLinkType() {
		case pg_query.SubLinkType_ANY_SUBLINK: // col IN (SELECT ...)
			if col := columnName(unwrapCast(s.GetTestexpr())); col != "" {
				return []string{col}
			}
		case pg_query.SubLinkType_EXISTS_SUBLINK:
			return outerColumns(s.GetSubselect(), table)
		}
	case n.GetFuncCall() != nil:
		f := n.GetFuncCall()
		if isIdentityFunc(f) {
			return nil
		}
		var cols []string
		for _, arg := range f.GetArgs() {
			if col := columnName(unwrapCast(arg)); col != "" {
				cols = append(cols, col)
			}
		}
		return cols
	}
	return nil
}

// conjuncts splits "a AND b AND c" into [a b c].
func conjuncts(n *pg_query.Node) []*pg_query.Node {
	if b := n.GetBoolExpr(); b != nil && b.GetBoolop() == pg_query.BoolExprType_AND_EXPR {
		var out []*pg_query.Node
		for _, arg := range b.GetArgs() {
			out = append(out, conjuncts(arg)...)
		}
		return out
	}
	return []*pg_query.Node{n}
}

// hasIdentity reports whether the subtree reads who the caller is.
func hasIdentity(n *pg_query.Node) bool {
	found := false
	walk(n, func(n *pg_query.Node) {
		if f := n.GetFuncCall(); f != nil && isIdentityFunc(f) {
			found = true
		}
		if v := n.GetSqlvalueFunction(); v != nil {
			switch v.GetOp() {
			case pg_query.SQLValueFunctionOp_SVFOP_CURRENT_USER,
				pg_query.SQLValueFunctionOp_SVFOP_SESSION_USER,
				pg_query.SQLValueFunctionOp_SVFOP_CURRENT_ROLE,
				pg_query.SQLValueFunctionOp_SVFOP_USER:
				found = true
			}
		}
	})
	return found
}

func isIdentityFunc(f *pg_query.FuncCall) bool {
	name := funcName(f)
	return name == "auth.uid" || name == "auth.jwt" || name == "current_setting" || name == "pg_catalog.current_setting"
}

// outerColumns finds "table.col" references inside an EXISTS subquery, which
// is how a subquery points back at the row being checked.
func outerColumns(n *pg_query.Node, table string) []string {
	var cols []string
	walk(n, func(n *pg_query.Node) {
		c := n.GetColumnRef()
		if c == nil || len(c.GetFields()) < 2 {
			return
		}
		f := c.GetFields()
		if f[len(f)-2].GetString_().GetSval() == table {
			cols = append(cols, f[len(f)-1].GetString_().GetSval())
		}
	})
	return cols
}

func columnName(n *pg_query.Node) string {
	c := n.GetColumnRef()
	if c == nil || len(c.GetFields()) == 0 {
		return ""
	}
	return c.GetFields()[len(c.GetFields())-1].GetString_().GetSval()
}

func funcName(f *pg_query.FuncCall) string {
	var parts []string
	for _, p := range f.GetFuncname() {
		parts = append(parts, p.GetString_().GetSval())
	}
	return strings.Join(parts, ".")
}

func isFunc(n *pg_query.Node, schema, name string) bool {
	f := n.GetFuncCall()
	return f != nil && funcName(f) == schema+"."+name
}

func opName(a *pg_query.A_Expr) string {
	if a.GetKind() != pg_query.A_Expr_Kind_AEXPR_OP || len(a.GetName()) == 0 {
		return ""
	}
	return a.GetName()[len(a.GetName())-1].GetString_().GetSval()
}

func isJSONOperator(op string) bool {
	return op == "->" || op == "->>" || op == "#>" || op == "#>>"
}

func stringConst(n *pg_query.Node) string {
	if c := unwrapCast(n).GetAConst(); c != nil && c.GetSval() != nil {
		return c.GetSval().GetSval()
	}
	return ""
}

// unwrapCast strips "::type" casts, which pg_get_expr adds generously.
func unwrapCast(n *pg_query.Node) *pg_query.Node {
	for n.GetTypeCast() != nil {
		n = n.GetTypeCast().GetArg()
	}
	return n
}

// walk calls fn on every Node in the tree. pg_query_go's tree is made of
// protobuf messages, so protobuf reflection lets one function visit every
// node type without a giant type switch.
func walk(n *pg_query.Node, fn func(*pg_query.Node)) {
	if n == nil {
		return
	}
	var visit func(m protoreflect.Message)
	visit = func(m protoreflect.Message) {
		if node, ok := m.Interface().(*pg_query.Node); ok {
			fn(node)
		}
		m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			switch {
			case fd.IsList() && fd.Message() != nil:
				for i := 0; i < v.List().Len(); i++ {
					visit(v.List().Get(i).Message())
				}
			case fd.Message() != nil && !fd.IsMap():
				visit(v.Message())
			}
			return true
		})
	}
	visit(n.ProtoReflect())
}
