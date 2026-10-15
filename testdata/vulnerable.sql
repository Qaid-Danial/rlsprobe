-- One deliberate mistake per rule. Run after supabase_stub.sql.
-- Every table except rls008_comments is FORCEd so RLS008 fires only once.
-- Two extra "app" roles exist so RLS010 and RLS011 have something to find:
-- scan with --roles anon,authenticated,app_bypass,app_owner.

CREATE ROLE app_bypass NOLOGIN BYPASSRLS;  -- RLS010
CREATE ROLE app_owner NOLOGIN;             -- RLS011

-- RLS001: RLS never enabled.
CREATE TABLE public.rls001_notes (id bigint PRIMARY KEY, body text);

-- RLS002: "anyone can read" on a table that is not meant to be public.
CREATE TABLE public.rls002_messages (id bigint PRIMARY KEY, user_id uuid, body text);
ALTER TABLE public.rls002_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rls002_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY "anyone can read" ON public.rls002_messages FOR SELECT TO anon, authenticated USING (true);

-- RLS003: the INSERT check validates the title but not who owns the row,
-- so a user can create rows in someone else's account.
CREATE TABLE public.rls003_todos (id bigint PRIMARY KEY, user_id uuid NOT NULL, title text);
ALTER TABLE public.rls003_todos ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rls003_todos FORCE ROW LEVEL SECURITY;
CREATE POLICY "own rows" ON public.rls003_todos FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "add todos" ON public.rls003_todos FOR INSERT TO authenticated WITH CHECK (title <> '');

-- RLS004: team membership read from user_metadata, which users can edit.
CREATE TABLE public.rls004_projects (id bigint PRIMARY KEY, team text);
ALTER TABLE public.rls004_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rls004_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY "team access" ON public.rls004_projects FOR SELECT TO authenticated
  USING ((auth.jwt() -> 'user_metadata' ->> 'team') = team);

-- RLS005: a view owned by postgres (superuser) over a protected table.
CREATE TABLE public.rls005_secrets (id bigint PRIMARY KEY, user_id uuid, secret text);
ALTER TABLE public.rls005_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rls005_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY "own secrets" ON public.rls005_secrets FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE VIEW public.rls005_all_secrets AS SELECT * FROM public.rls005_secrets;

-- RLS006: an admin helper anyone can call through /rpc.
CREATE FUNCTION public.rls006_delete_user(target uuid) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  DELETE FROM public.rls003_todos WHERE user_id = target
$$;

-- RLS007: RLS on, policies forgotten.
CREATE TABLE public.rls007_audit (id bigint PRIMARY KEY, event text);
ALTER TABLE public.rls007_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rls007_audit FORCE ROW LEVEL SECURITY;

-- RLS008: RLS on and correct, but not forced.
CREATE TABLE public.rls008_comments (id bigint PRIMARY KEY, user_id uuid, body text);
ALTER TABLE public.rls008_comments ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own comments" ON public.rls008_comments FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- RLS009: SECURITY DEFINER without search_path. Not callable by the API,
-- so it shows RLS009 on its own.
CREATE FUNCTION public.rls009_count_todos() RETURNS bigint
  LANGUAGE sql SECURITY DEFINER AS $$ SELECT count(*) FROM rls003_todos $$;
REVOKE EXECUTE ON FUNCTION public.rls009_count_todos() FROM PUBLIC, anon, authenticated, service_role;

-- RLS010: see app_bypass above.

-- RLS011: the app role owns the table and RLS is not forced.
CREATE TABLE public.rls011_invoices (id bigint PRIMARY KEY, user_id uuid, amount numeric);
ALTER TABLE public.rls011_invoices ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own invoices" ON public.rls011_invoices FOR SELECT TO authenticated USING (auth.uid() = user_id);
ALTER TABLE public.rls011_invoices OWNER TO app_owner;
