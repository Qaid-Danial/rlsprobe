-- The same app, done right. Run after supabase_stub.sql; expect zero findings
-- when scanning with the default roles (anon, authenticated).

-- Private profile data: owner-only, using the (select auth.uid()) form
-- Supabase recommends because it is evaluated once per query, not per row.
CREATE TABLE public.todos (id bigint PRIMARY KEY, user_id uuid NOT NULL, title text);
ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.todos FORCE ROW LEVEL SECURITY;
CREATE POLICY "read own" ON public.todos FOR SELECT TO authenticated USING ((select auth.uid()) = user_id);
CREATE POLICY "insert own" ON public.todos FOR INSERT TO authenticated WITH CHECK ((select auth.uid()) = user_id);
-- No WITH CHECK: Postgres reuses USING for the new row, so this is safe.
CREATE POLICY "update own" ON public.todos FOR UPDATE TO authenticated USING ((select auth.uid()) = user_id);
CREATE POLICY "delete own" ON public.todos FOR DELETE TO authenticated USING ((select auth.uid()) = user_id);

-- Team data: membership checked through a members table.
CREATE TABLE public.members (team_id bigint, user_id uuid, PRIMARY KEY (team_id, user_id));
ALTER TABLE public.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.members FORCE ROW LEVEL SECURITY;
CREATE POLICY "see own memberships" ON public.members FOR SELECT TO authenticated USING (user_id = (select auth.uid()));

CREATE TABLE public.docs (id bigint PRIMARY KEY, team_id bigint NOT NULL, body text);
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.docs FORCE ROW LEVEL SECURITY;
CREATE POLICY "team reads" ON public.docs FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.members m WHERE m.team_id = docs.team_id AND m.user_id = (select auth.uid())));
CREATE POLICY "team writes" ON public.docs FOR INSERT TO authenticated
  WITH CHECK (team_id IN (SELECT m.team_id FROM public.members m WHERE m.user_id = (select auth.uid())));

-- Public on purpose, and annotated so rlsprobe knows.
CREATE TABLE public.announcements (id bigint PRIMARY KEY, body text);
ALTER TABLE public.announcements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.announcements FORCE ROW LEVEL SECURITY;
CREATE POLICY "public read" ON public.announcements FOR SELECT TO anon, authenticated USING (true);
COMMENT ON TABLE public.announcements IS 'Shown on the landing page. rlsprobe:ignore=RLS002';

-- A view that runs as the caller, so RLS on todos still applies.
CREATE VIEW public.my_todos WITH (security_invoker = true) AS SELECT id, title FROM public.todos;

-- A definer function that is locked down: fixed search_path, no API access.
CREATE FUNCTION public.todo_count() RETURNS bigint
  LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$ SELECT count(*) FROM public.todos $$;
REVOKE EXECUTE ON FUNCTION public.todo_count() FROM PUBLIC, anon, authenticated, service_role;
