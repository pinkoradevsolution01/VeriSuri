-- Recovery workflow support and verified-only public fraud advisories.
-- Run after the existing VeriSuri migrations in the Supabase SQL Editor.

alter table public.fraud_alerts
  add column if not exists status text not null default 'draft' check (status in ('draft', 'pending', 'verified', 'rejected', 'expired')),
  add column if not exists source_name text,
  add column if not exists source_url text,
  add column if not exists affected_platform text,
  add column if not exists region text,
  add column if not exists review_at timestamptz,
  add column if not exists expires_at timestamptz,
  add column if not exists reviewed_by uuid references auth.users(id),
  add column if not exists reviewed_at timestamptz;

-- Legacy records must be reviewed again before publication.
update public.fraud_alerts set published = false, status = 'draft'
where status = 'draft' and published = true;

create index if not exists fraud_alerts_public_idx
  on public.fraud_alerts (published_at desc)
  where published = true and status = 'verified';

create or replace function public.create_moderated_alert(
  p_title text,
  p_summary text,
  p_severity public.alert_severity,
  p_source_name text,
  p_source_url text,
  p_affected_platform text,
  p_region text default null,
  p_review_at timestamptz default null,
  p_expires_at timestamptz default null
) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_alert_id uuid;
begin
  if not public.is_staff() then raise exception 'Moderator access is required'; end if;
  if char_length(trim(coalesce(p_title, ''))) < 8 or char_length(trim(coalesce(p_summary, ''))) < 20 then
    raise exception 'An alert title and summary with sufficient detail are required';
  end if;
  if char_length(trim(coalesce(p_source_name, ''))) < 2 or trim(coalesce(p_source_url, '')) !~ '^https://' then
    raise exception 'An official HTTPS source name and URL are required';
  end if;
  if char_length(trim(coalesce(p_affected_platform, ''))) < 2 then raise exception 'An affected platform is required'; end if;
  if p_review_at is null or p_expires_at is null or p_review_at <= now() or p_expires_at <= p_review_at then
    raise exception 'A future review date and a later expiry date are required';
  end if;
  insert into public.fraud_alerts (title, summary, severity, status, published, source_name, source_url, affected_platform, region, review_at, expires_at)
  values (trim(p_title), trim(p_summary), p_severity, 'pending', false, trim(p_source_name), trim(p_source_url), trim(p_affected_platform), nullif(trim(coalesce(p_region, '')), ''), p_review_at, p_expires_at)
  returning id into v_alert_id;
  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'alert_submitted_for_review', 'fraud_alert', v_alert_id::text, jsonb_build_object('source_name', trim(p_source_name)));
  return v_alert_id;
end;
$$;

create or replace function public.review_moderated_alert(
  p_alert_id uuid,
  p_decision text
) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff() then raise exception 'Moderator access is required'; end if;
  if p_decision not in ('verified', 'rejected') then raise exception 'Invalid alert decision'; end if;
  if p_decision = 'verified' then
    update public.fraud_alerts
    set status = 'verified', published = true, published_at = now(), reviewed_by = auth.uid(), reviewed_at = now()
    where id = p_alert_id and status = 'pending'
      and source_name is not null and source_url ~ '^https://'
      and affected_platform is not null and review_at > now() and expires_at > review_at;
  else
    update public.fraud_alerts
    set status = 'rejected', published = false, reviewed_by = auth.uid(), reviewed_at = now()
    where id = p_alert_id and status = 'pending';
  end if;
  if not found then raise exception 'Alert is unavailable or does not meet publication requirements'; end if;
  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'alert_reviewed', 'fraud_alert', p_alert_id::text, jsonb_build_object('decision', p_decision));
end;
$$;

revoke all on function public.create_moderated_alert(text, text, public.alert_severity, text, text, text, text, timestamptz, timestamptz) from public;
grant execute on function public.create_moderated_alert(text, text, public.alert_severity, text, text, text, text, timestamptz, timestamptz) to authenticated;
revoke all on function public.review_moderated_alert(uuid, text) from public;
grant execute on function public.review_moderated_alert(uuid, text) to authenticated;
