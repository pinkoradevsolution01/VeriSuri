-- Account security: private device/activity history plus MFA-gated staff actions.
-- Run after the prior VeriSuri migrations in the Supabase SQL Editor.

create table if not exists public.recognized_devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  device_fingerprint text not null,
  device_name text not null,
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (user_id, device_fingerprint)
);

create table if not exists public.account_security_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  event_type text not null check (char_length(event_type) between 3 and 80),
  details text,
  created_at timestamptz not null default now()
);

create index if not exists recognized_devices_owner_seen_idx on public.recognized_devices (user_id, last_seen_at desc);
create index if not exists account_security_events_owner_created_idx on public.account_security_events (user_id, created_at desc);

alter table public.recognized_devices enable row level security;
alter table public.account_security_events enable row level security;

drop policy if exists "own_recognized_devices" on public.recognized_devices;
create policy "own_recognized_devices" on public.recognized_devices
  for all to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

drop policy if exists "own_account_security_events" on public.account_security_events;
create policy "own_account_security_events" on public.account_security_events
  for all to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- Staff accounts must have completed MFA (AAL2) before reviewing reports,
-- managing alerts, or accessing staff-only data. Non-staff ownership policies
-- remain unaffected.
create or replace function public.is_staff_mfa() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_staff() and coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2'
$$;

drop policy if exists "staff_mfa_gate_reports" on public.scam_reports;
create policy "staff_mfa_gate_reports" on public.scam_reports
  as restrictive for all to authenticated
  using (not public.is_staff() or public.is_staff_mfa())
  with check (not public.is_staff() or public.is_staff_mfa());

drop policy if exists "staff_mfa_gate_entities" on public.reported_entities;
create policy "staff_mfa_gate_entities" on public.reported_entities
  as restrictive for all to authenticated
  using (not public.is_staff() or public.is_staff_mfa())
  with check (not public.is_staff() or public.is_staff_mfa());

drop policy if exists "staff_mfa_gate_alerts" on public.fraud_alerts;
create policy "staff_mfa_gate_alerts" on public.fraud_alerts
  as restrictive for all to authenticated
  using (not public.is_staff() or public.is_staff_mfa())
  with check (not public.is_staff() or public.is_staff_mfa());

drop policy if exists "staff_mfa_gate_moderation" on public.moderation_actions;
create policy "staff_mfa_gate_moderation" on public.moderation_actions
  as restrictive for all to authenticated
  using (not public.is_staff() or public.is_staff_mfa())
  with check (not public.is_staff() or public.is_staff_mfa());

drop policy if exists "staff_mfa_gate_audit" on public.audit_logs;
create policy "staff_mfa_gate_audit" on public.audit_logs
  as restrictive for all to authenticated
  using (not public.is_staff() or public.is_staff_mfa())
  with check (not public.is_staff() or public.is_staff_mfa());

create or replace function public.review_scam_report(
  p_report_id uuid,
  p_status public.report_status,
  p_reason text default null,
  p_training_status text default null
) returns void
language plpgsql security definer set search_path = public as $$
declare v_reporter uuid;
begin
  if not public.is_staff_mfa() then raise exception 'Complete MFA before performing moderator actions'; end if;
  if p_status not in ('confirmed', 'rejected') then raise exception 'Invalid moderation decision'; end if;
  update public.scam_reports
  set status = p_status, reviewed_by = auth.uid(), reviewed_at = now()
  where id = p_report_id and status = 'pending'
  returning reporter_id into v_reporter;
  if not found then raise exception 'Report is unavailable or already reviewed'; end if;
  update public.reported_entities set status = p_status where report_id = p_report_id and status = 'pending';
  insert into public.moderation_actions (report_id, moderator_id, action, reason)
  values (p_report_id, auth.uid(), p_status::text, nullif(trim(coalesce(p_reason, '')), ''));
  if p_training_status is not null then
    if p_training_status not in ('approved', 'rejected') then raise exception 'Invalid training decision'; end if;
    update public.training_examples set status = p_training_status, reviewed_by = auth.uid(), reviewed_at = now()
    where report_id = p_report_id and status = 'pending';
  end if;
  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'report_moderated', 'scam_report', p_report_id::text, jsonb_build_object('status', p_status, 'training_status', p_training_status));
end;
$$;

create or replace function public.create_moderated_alert(
  p_title text, p_summary text, p_severity public.alert_severity,
  p_source_name text, p_source_url text, p_affected_platform text,
  p_region text default null, p_review_at timestamptz default null, p_expires_at timestamptz default null
) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_alert_id uuid;
begin
  if not public.is_staff_mfa() then raise exception 'Complete MFA before performing moderator actions'; end if;
  if char_length(trim(coalesce(p_title, ''))) < 8 or char_length(trim(coalesce(p_summary, ''))) < 20 then raise exception 'An alert title and summary with sufficient detail are required'; end if;
  if char_length(trim(coalesce(p_source_name, ''))) < 2 or trim(coalesce(p_source_url, '')) !~ '^https://' then raise exception 'An official HTTPS source name and URL are required'; end if;
  if char_length(trim(coalesce(p_affected_platform, ''))) < 2 then raise exception 'An affected platform is required'; end if;
  if p_review_at is null or p_expires_at is null or p_review_at <= now() or p_expires_at <= p_review_at then raise exception 'A future review date and a later expiry date are required'; end if;
  insert into public.fraud_alerts (title, summary, severity, status, published, source_name, source_url, affected_platform, region, review_at, expires_at)
  values (trim(p_title), trim(p_summary), p_severity, 'pending', false, trim(p_source_name), trim(p_source_url), trim(p_affected_platform), nullif(trim(coalesce(p_region, '')), ''), p_review_at, p_expires_at)
  returning id into v_alert_id;
  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'alert_submitted_for_review', 'fraud_alert', v_alert_id::text, jsonb_build_object('source_name', trim(p_source_name)));
  return v_alert_id;
end;
$$;

create or replace function public.review_moderated_alert(p_alert_id uuid, p_decision text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff_mfa() then raise exception 'Complete MFA before performing moderator actions'; end if;
  if p_decision not in ('verified', 'rejected') then raise exception 'Invalid alert decision'; end if;
  if p_decision = 'verified' then
    update public.fraud_alerts set status = 'verified', published = true, published_at = now(), reviewed_by = auth.uid(), reviewed_at = now()
    where id = p_alert_id and status = 'pending' and source_name is not null and source_url ~ '^https://' and affected_platform is not null and review_at > now() and expires_at > review_at;
  else
    update public.fraud_alerts set status = 'rejected', published = false, reviewed_by = auth.uid(), reviewed_at = now()
    where id = p_alert_id and status = 'pending';
  end if;
  if not found then raise exception 'Alert is unavailable or does not meet publication requirements'; end if;
  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'alert_reviewed', 'fraud_alert', p_alert_id::text, jsonb_build_object('decision', p_decision));
end;
$$;

revoke all on function public.review_scam_report(uuid, public.report_status, text, text) from public;
grant execute on function public.review_scam_report(uuid, public.report_status, text, text) to authenticated;
revoke all on function public.create_moderated_alert(text, text, public.alert_severity, text, text, text, text, timestamptz, timestamptz) from public;
grant execute on function public.create_moderated_alert(text, text, public.alert_severity, text, text, text, text, timestamptz, timestamptz) to authenticated;
revoke all on function public.review_moderated_alert(uuid, text) from public;
grant execute on function public.review_moderated_alert(uuid, text) to authenticated;
