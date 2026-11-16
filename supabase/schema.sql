-- Apply in Supabase SQL editor. Keep the service-role key on FastAPI/Vercel only.
create extension if not exists pgcrypto;
create type public.app_role as enum ('user', 'moderator', 'admin');
create type public.report_status as enum ('pending', 'confirmed', 'rejected', 'appealed');
create type public.entity_kind as enum ('gcash', 'maya', 'bank', 'phone', 'url', 'social');
create type public.alert_severity as enum ('low', 'medium', 'high');

create table public.profiles (id uuid primary key references auth.users(id) on delete cascade, display_name text, role public.app_role not null default 'user', created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create table public.scan_results (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id) on delete set null, scan_type text not null check (scan_type in ('message','link','payment','report_lookup')), input_hash text not null, score smallint not null check (score between 0 and 100), verdict text not null, signals jsonb not null default '[]', engine_version text not null, created_at timestamptz not null default now());
create table public.scam_reports (id uuid primary key default gen_random_uuid(), reporter_id uuid not null references auth.users(id) on delete cascade, narrative text not null, incident_at timestamptz, status public.report_status not null default 'pending', reviewed_by uuid references auth.users(id), reviewed_at timestamptz, created_at timestamptz not null default now());
create table public.reported_entities (id uuid primary key default gen_random_uuid(), report_id uuid not null references public.scam_reports(id) on delete cascade, entity_type public.entity_kind not null, entity_hash text not null, entity_last4 text, status public.report_status not null default 'pending', created_at timestamptz not null default now(), unique(report_id, entity_type, entity_hash));
create index reported_entities_match_idx on public.reported_entities(entity_type, entity_hash) where status = 'confirmed';
create table public.report_evidence (id uuid primary key default gen_random_uuid(), report_id uuid not null references public.scam_reports(id) on delete cascade, storage_path text not null unique, original_filename text not null, mime_type text not null, created_at timestamptz not null default now());
create table public.fraud_cases (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id), status text not null default 'open', notes text, created_at timestamptz not null default now());
create table public.fraud_alerts (id uuid primary key default gen_random_uuid(), title text not null, summary text not null, severity public.alert_severity not null, published boolean not null default false, published_at timestamptz, created_at timestamptz not null default now());
create table public.moderation_actions (id uuid primary key default gen_random_uuid(), report_id uuid references public.scam_reports(id) on delete cascade, moderator_id uuid not null references auth.users(id), action text not null, reason text, created_at timestamptz not null default now());
create table public.model_versions (id uuid primary key default gen_random_uuid(), version text not null unique, metrics jsonb not null default '{}', artifact_uri text, created_at timestamptz not null default now());
create table public.audit_logs (id bigint generated always as identity primary key, actor_id uuid references auth.users(id), action text not null, resource_type text not null, resource_id text, metadata jsonb not null default '{}', created_at timestamptz not null default now());

alter table public.profiles enable row level security; alter table public.scan_results enable row level security; alter table public.scam_reports enable row level security; alter table public.reported_entities enable row level security; alter table public.report_evidence enable row level security; alter table public.fraud_cases enable row level security; alter table public.fraud_alerts enable row level security; alter table public.moderation_actions enable row level security; alter table public.model_versions enable row level security; alter table public.audit_logs enable row level security;
create or replace function public.is_staff() returns boolean language sql stable security definer set search_path = public as $$ select exists(select 1 from public.profiles where id = auth.uid() and role in ('moderator','admin')) $$;
create policy "own_profile" on public.profiles for select using (id = auth.uid());
create policy "own_scans" on public.scan_results for all using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "create_reports" on public.scam_reports for insert with check (reporter_id = auth.uid());
create policy "read_reports" on public.scam_reports for select using (reporter_id = auth.uid() or public.is_staff());
create policy "staff_reports" on public.scam_reports for all using (public.is_staff()) with check (public.is_staff());
create policy "read_entities" on public.reported_entities for select using (exists(select 1 from public.scam_reports r where r.id = report_id and (r.reporter_id = auth.uid() or public.is_staff())));
create policy "add_own_entities" on public.reported_entities for insert with check (exists(select 1 from public.scam_reports r where r.id = report_id and r.reporter_id = auth.uid() and r.status = 'pending'));
create policy "staff_entities" on public.reported_entities for all using (public.is_staff()) with check (public.is_staff());
create policy "read_evidence" on public.report_evidence for select using (exists(select 1 from public.scam_reports r where r.id = report_id and (r.reporter_id = auth.uid() or public.is_staff())));
create policy "own_cases" on public.fraud_cases for all using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "published_alerts" on public.fraud_alerts for select using (published = true or public.is_staff());
create policy "staff_alerts" on public.fraud_alerts for all using (public.is_staff()) with check (public.is_staff());
create policy "staff_moderation" on public.moderation_actions for all using (public.is_staff()) with check (public.is_staff());
create policy "staff_models" on public.model_versions for select using (public.is_staff());
create policy "staff_audit" on public.audit_logs for select using (public.is_staff());
