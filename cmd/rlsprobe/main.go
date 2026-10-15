// Command rlsprobe audits Postgres Row Level Security from the catalog.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Qaid-Danial/rlsprobe/internal/catalog"
	"github.com/Qaid-Danial/rlsprobe/internal/checks"
	"github.com/Qaid-Danial/rlsprobe/internal/report"
)

// version is set at build time: go build -ldflags "-X main.version=v0.1.0"
var version = "dev"

// Exit codes: 0 clean, 1 findings at or above --fail-on, 2 the tool itself failed.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	db, profile, roles, schemas, format, failOn, dumpSnapshot, snapshot string
	showVersion                                                         bool
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rlsprobe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.db, "db", "", "Postgres connection string (default: $RLSPROBE_DB). Prefer the env var: flags end up in shell history and ps output")
	fs.StringVar(&o.profile, "profile", "supabase", "supabase or postgres")
	fs.StringVar(&o.roles, "roles", "", "comma-separated exposed roles (supabase default: anon,authenticated; required for postgres)")
	fs.StringVar(&o.schemas, "schemas", "public", "comma-separated schemas to audit")
	fs.StringVar(&o.format, "format", "table", "table or json")
	fs.StringVar(&o.failOn, "fail-on", "high", "exit 1 if any finding is at or above: info, low, medium, high, critical")
	fs.StringVar(&o.dumpSnapshot, "dump-snapshot", "", "also write the catalog snapshot as JSON to this file")
	fs.StringVar(&o.snapshot, "snapshot", "", "audit a saved snapshot file instead of connecting to a database")
	fs.BoolVar(&o.showVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if o.showVersion {
		fmt.Fprintln(stdout, "rlsprobe", version)
		return exitOK
	}
	if err := audit(o, stdout, stderr); err != nil {
		if errors.Is(err, errFindings) {
			return exitFindings
		}
		fmt.Fprintln(stderr, "rlsprobe:", err)
		return exitError
	}
	return exitOK
}

var errFindings = errors.New("findings at or above threshold")

func audit(o options, stdout, stderr io.Writer) error {
	if o.profile != "supabase" && o.profile != "postgres" {
		return fmt.Errorf("unknown profile %q (want supabase or postgres)", o.profile)
	}
	threshold, err := checks.ParseSeverity(o.failOn)
	if err != nil {
		return err
	}
	renderer, err := report.For(o.format)
	if err != nil {
		return err
	}

	snap, err := loadSnapshot(o)
	if err != nil {
		return err
	}
	for _, r := range snap.ExposedRoles {
		if !r.Exists {
			fmt.Fprintf(stderr, "rlsprobe: warning: role %q does not exist, skipped\n", r.Name)
		}
	}
	if o.dumpSnapshot != "" {
		if err := writeJSON(o.dumpSnapshot, snap); err != nil {
			return err
		}
	}

	findings := checks.Run(snap, o.profile)
	if err := renderer.Render(stdout, findings); err != nil {
		return err
	}
	if report.Failed(findings, threshold) {
		return errFindings
	}
	return nil
}

func loadSnapshot(o options) (*catalog.Snapshot, error) {
	if o.snapshot != "" {
		data, err := os.ReadFile(o.snapshot)
		if err != nil {
			return nil, err
		}
		var s catalog.Snapshot
		return &s, json.Unmarshal(data, &s)
	}

	dsn := o.db
	if dsn == "" {
		dsn = os.Getenv("RLSPROBE_DB")
	}
	if dsn == "" {
		return nil, errors.New("no database: pass --db or set RLSPROBE_DB")
	}
	roles := splitList(o.roles)
	if len(roles) == 0 {
		if o.profile == "postgres" {
			return nil, errors.New("--profile postgres needs --roles (the roles your app connects as)")
		}
		roles = []string{"anon", "authenticated"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		// pgx prints user, database and host but masks the password as xxxxx.
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	return catalog.Load(ctx, conn, splitList(o.schemas), roles)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
