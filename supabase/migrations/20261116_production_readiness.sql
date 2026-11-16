-- VeriSuri production-readiness migration. Run this once in the Supabase SQL editor.
-- It adds explicit consent records, a reviewed training-data queue, account deletion
-- requests, a profile trigger, and tightly scoped reviewer RPCs.

alter table public.scam_reports
  add column if not exists privacy_notice_version text not null default '2026-11-16',
  add column if not exists privacy_acknowledged_at timestamptz,
  add column if not exists training_consent boolean not null default false,
  add column if not exists training_consent_version text,
  add column if not exists training_consent_at timestamptz,
  add column if not exists data_deletion_requested_at timestamptz;

create table if not exists public.training_examples (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null unique references public.scam_reports(id) on delete cascade,
  reporter_id uuid not null references auth.users(id) on delete cascade,
  text_redacted text not null check (char_length(text_redacted) between 30 and 10000),
  language text not null default 'en',
  label smallint check (label in (0, 1)),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'withdrawn')),
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  consent_version text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.privacy_requests (
  id uuid primary key default gen_random_uuid(),
  requester_id uuid not null references auth.users(id) on delete cascade,
  request_type text not null check (request_type in ('deletion')),
  status text not null default 'pending' check (status in ('pending', 'in_progress', 'completed', 'rejected')),
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  unique (requester_id, request_type, status)
);

alter table public.training_examples enable row level security;
alter table public.privacy_requests enable row level security;

drop policy if exists "create_reports" on public.scam_reports;
drop policy if exists "add_own_entities" on public.reported_entities;
create policy "own_privacy_requests" on public.privacy_requests for select using (requester_id = auth.uid() or public.is_staff());
create policy "staff_privacy_requests" on public.privacy_requests for update using (public.is_staff()) with check (public.is_staff());
create policy "staff_training_examples" on public.training_examples for select using (public.is_staff());
create policy "staff_update_training_examples" on public.training_examples for update using (public.is_staff()) with check (public.is_staff());

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', new.email))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Backfill profiles for accounts that existed before the trigger was installed.
insert into public.profiles (id, display_name)
select id, coalesce(raw_user_meta_data ->> 'full_name', email)
from auth.users
on conflict (id) do nothing;

create or replace function public.submit_scam_report(
  p_entity_type public.entity_kind,
  p_entity_value text,
  p_narrative text,
  p_privacy_notice_version text,
  p_acknowledged_safe_submission boolean,
  p_training_consent boolean default false,
  p_redacted_training_sample text default null
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_report_id uuid;
  v_entity_hash text;
begin
  if auth.uid() is null then raise exception 'Sign in is required'; end if;
  if not p_acknowledged_safe_submission then raise exception 'Safe-submission acknowledgement is required'; end if;
  if char_length(trim(coalesce(p_entity_value, ''))) < 3 or char_length(trim(coalesce(p_narrative, ''))) < 20 then
    raise exception 'A valid identifier and incident narrative are required';
  end if;
  if p_training_consent and char_length(trim(coalesce(p_redacted_training_sample, ''))) < 30 then
    raise exception 'A redacted message sample of at least 30 characters is required when training consent is selected';
  end if;

  insert into public.scam_reports (
    reporter_id, narrative, privacy_notice_version, privacy_acknowledged_at,
    training_consent, training_consent_version, training_consent_at
  ) values (
    auth.uid(), trim(p_narrative), trim(p_privacy_notice_version), now(),
    p_training_consent, case when p_training_consent then trim(p_privacy_notice_version) else null end,
    case when p_training_consent then now() else null end
  ) returning id into v_report_id;

  v_entity_hash := encode(digest(lower(trim(p_entity_value)), 'sha256'), 'hex');
  insert into public.reported_entities (report_id, entity_type, entity_hash, entity_last4)
  values (v_report_id, p_entity_type, v_entity_hash, right(trim(p_entity_value), 4));

  if p_training_consent then
    insert into public.training_examples (report_id, reporter_id, text_redacted, label, consent_version)
    values (v_report_id, auth.uid(), trim(p_redacted_training_sample), 1, trim(p_privacy_notice_version));
  end if;

  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'report_submitted', 'scam_report', v_report_id::text,
    jsonb_build_object('training_consent', p_training_consent, 'privacy_notice_version', p_privacy_notice_version));
  return v_report_id;
end;
$$;

create or replace function public.review_scam_report(
  p_report_id uuid,
  p_status public.report_status,
  p_reason text default null,
  p_training_status text default null
) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff() then raise exception 'Moderator access is required'; end if;
  if p_status not in ('confirmed', 'rejected') then raise exception 'Invalid review decision'; end if;
  if p_training_status is not null and p_training_status not in ('approved', 'rejected') then raise exception 'Invalid training decision'; end if;

  update public.scam_reports set status = p_status, reviewed_by = auth.uid(), reviewed_at = now() where id = p_report_id and status = 'pending';
  if not found then raise exception 'Report is unavailable for review'; end if;
  update public.reported_entities set status = p_status where report_id = p_report_id;
  if p_training_status is not null then
    update public.training_examples set status = p_training_status, reviewed_by = auth.uid(), reviewed_at = now() where report_id = p_report_id and status = 'pending';
  end if;
  insert into public.moderation_actions (report_id, moderator_id, action, reason)
  values (p_report_id, auth.uid(), p_status::text, nullif(trim(coalesce(p_reason, '')), ''));
  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'report_reviewed', 'scam_report', p_report_id::text, jsonb_build_object('decision', p_status, 'training_status', p_training_status));
end;
$$;

create or replace function public.request_privacy_deletion()
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Sign in is required'; end if;
  insert into public.privacy_requests (requester_id, request_type)
  values (auth.uid(), 'deletion') on conflict (requester_id, request_type, status) do nothing;
  update public.scam_reports set data_deletion_requested_at = now()
  where reporter_id = auth.uid() and data_deletion_requested_at is null;
  update public.training_examples set status = 'withdrawn'
  where reporter_id = auth.uid() and status = 'pending';
  insert into public.audit_logs (actor_id, action, resource_type, metadata)
  values (auth.uid(), 'privacy_deletion_requested', 'privacy_request', '{}'::jsonb);
end;
$$;

revoke all on function public.submit_scam_report(public.entity_kind, text, text, text, boolean, boolean, text) from public;
grant execute on function public.submit_scam_report(public.entity_kind, text, text, text, boolean, boolean, text) to authenticated;
revoke all on function public.review_scam_report(uuid, public.report_status, text, text) from public;
grant execute on function public.review_scam_report(uuid, public.report_status, text, text) to authenticated;
revoke all on function public.request_privacy_deletion() from public;
grant execute on function public.request_privacy_deletion() to authenticated;
