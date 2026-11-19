-- Structured reporting and duplicate cues for moderator review.
-- Run after 20261116_production_readiness.sql in the Supabase SQL Editor.

alter table public.scam_reports
  add column if not exists scam_type text not null default 'other' check (scam_type in ('phishing', 'investment', 'marketplace', 'impersonation', 'loan', 'romance', 'job', 'delivery', 'other')),
  add column if not exists payment_provider text not null default 'not_applicable' check (payment_provider in ('gcash', 'maya', 'bank', 'card', 'crypto', 'not_applicable')),
  add column if not exists amount_range text not null default 'not_stated' check (amount_range in ('under_1000', '1000_4999', '5000_19999', '20000_99999', '100000_plus', 'not_stated')),
  add column if not exists incident_channel text not null default 'other' check (incident_channel in ('sms', 'messaging_app', 'social_media', 'email', 'call', 'website', 'marketplace', 'other')),
  add column if not exists redacted_evidence text check (redacted_evidence is null or char_length(redacted_evidence) between 20 and 10000),
  add column if not exists duplicate_of uuid references public.scam_reports(id) on delete set null,
  add column if not exists duplicate_count integer not null default 0 check (duplicate_count >= 0);

create index if not exists scam_reports_duplicate_of_idx on public.scam_reports(duplicate_of) where duplicate_of is not null;

drop function if exists public.submit_scam_report(public.entity_kind, text, text, text, boolean, boolean, text);

create function public.submit_scam_report(
  p_entity_type public.entity_kind,
  p_entity_value text,
  p_narrative text,
  p_privacy_notice_version text,
  p_acknowledged_safe_submission boolean,
  p_training_consent boolean default false,
  p_redacted_training_sample text default null,
  p_scam_type text default 'other',
  p_payment_provider text default 'not_applicable',
  p_amount_range text default 'not_stated',
  p_incident_at timestamptz default null,
  p_incident_channel text default 'other',
  p_redacted_evidence text default null
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_report_id uuid;
  v_entity_hash text;
  v_duplicate_of uuid;
  v_duplicate_count integer;
begin
  if auth.uid() is null then raise exception 'Sign in is required'; end if;
  if not p_acknowledged_safe_submission then raise exception 'Safe-submission acknowledgement is required'; end if;
  if char_length(trim(coalesce(p_entity_value, ''))) < 3 or char_length(trim(coalesce(p_narrative, ''))) < 20 then
    raise exception 'A valid identifier and incident narrative are required';
  end if;
  if p_training_consent and char_length(trim(coalesce(p_redacted_training_sample, ''))) < 30 then
    raise exception 'A redacted message sample of at least 30 characters is required when training consent is selected';
  end if;
  if p_redacted_evidence is not null and char_length(trim(p_redacted_evidence)) between 1 and 19 then
    raise exception 'Redacted evidence must be at least 20 characters or left blank';
  end if;
  if p_scam_type not in ('phishing', 'investment', 'marketplace', 'impersonation', 'loan', 'romance', 'job', 'delivery', 'other') then raise exception 'Invalid scam type'; end if;
  if p_payment_provider not in ('gcash', 'maya', 'bank', 'card', 'crypto', 'not_applicable') then raise exception 'Invalid payment provider'; end if;
  if p_amount_range not in ('under_1000', '1000_4999', '5000_19999', '20000_99999', '100000_plus', 'not_stated') then raise exception 'Invalid amount range'; end if;
  if p_incident_channel not in ('sms', 'messaging_app', 'social_media', 'email', 'call', 'website', 'marketplace', 'other') then raise exception 'Invalid incident channel'; end if;

  v_entity_hash := encode(digest(lower(trim(p_entity_value)), 'sha256'), 'hex');
  select count(*) into v_duplicate_count
  from public.scam_reports r
  join public.reported_entities e on e.report_id = r.id
  where e.entity_type = p_entity_type and e.entity_hash = v_entity_hash and r.status in ('pending', 'confirmed');
  select r.id into v_duplicate_of
  from public.scam_reports r
  join public.reported_entities e on e.report_id = r.id
  where e.entity_type = p_entity_type and e.entity_hash = v_entity_hash and r.status in ('pending', 'confirmed')
  order by r.created_at asc
  limit 1;

  insert into public.scam_reports (
    reporter_id, narrative, incident_at, scam_type, payment_provider, amount_range, incident_channel,
    redacted_evidence, duplicate_of, duplicate_count, privacy_notice_version, privacy_acknowledged_at,
    training_consent, training_consent_version, training_consent_at
  ) values (
    auth.uid(), trim(p_narrative), p_incident_at, p_scam_type, p_payment_provider, p_amount_range, p_incident_channel,
    nullif(trim(coalesce(p_redacted_evidence, '')), ''), v_duplicate_of, v_duplicate_count, trim(p_privacy_notice_version), now(),
    p_training_consent, case when p_training_consent then trim(p_privacy_notice_version) else null end,
    case when p_training_consent then now() else null end
  ) returning id into v_report_id;

  insert into public.reported_entities (report_id, entity_type, entity_hash, entity_last4)
  values (v_report_id, p_entity_type, v_entity_hash, right(trim(p_entity_value), 4));

  if p_training_consent then
    insert into public.training_examples (report_id, reporter_id, text_redacted, label, consent_version)
    values (v_report_id, auth.uid(), trim(p_redacted_training_sample), 1, trim(p_privacy_notice_version));
  end if;

  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'report_submitted', 'scam_report', v_report_id::text,
    jsonb_build_object('training_consent', p_training_consent, 'duplicate_count', v_duplicate_count, 'privacy_notice_version', p_privacy_notice_version));
  return v_report_id;
end;
$$;

revoke all on function public.submit_scam_report(public.entity_kind, text, text, text, boolean, boolean, text, text, text, text, timestamptz, text, text) from public;
grant execute on function public.submit_scam_report(public.entity_kind, text, text, text, boolean, boolean, text, text, text, text, timestamptz, text, text) to authenticated;
