-- Opt-in public contributor directory. Apply in the Supabase SQL editor.
-- No contributor or submitted identifier is published unless the reporter opted in
-- and a moderator confirmed the report.

alter table public.scam_reports
  add column if not exists public_contributor_opt_in boolean not null default false,
  add column if not exists public_contributor_name text,
  add column if not exists public_reference text;

create index if not exists scam_reports_public_contributors_idx
  on public.scam_reports(created_at desc)
  where status = 'confirmed' and public_contributor_opt_in = true;
