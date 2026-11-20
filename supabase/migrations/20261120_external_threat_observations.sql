-- Moderator-curated external threat reports. These are cautionary observations,
-- never confirmed scam verdicts, and expire unless reviewed again.

create table if not exists public.external_threat_observations (
  id uuid primary key default gen_random_uuid(),
  canonical_url text not null unique,
  source_name text not null,
  source_url text not null check (source_url ~ '^https://'),
  evidence_status text not null default 'reported' check (evidence_status in ('reported', 'confirmed', 'rejected')),
  expires_at timestamptz not null,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);
create index if not exists external_threat_observations_lookup_idx on public.external_threat_observations (canonical_url, expires_at)
  where evidence_status in ('reported', 'confirmed');
alter table public.external_threat_observations enable row level security;

drop policy if exists "staff_mfa_external_threat_observations" on public.external_threat_observations;
create policy "staff_mfa_external_threat_observations" on public.external_threat_observations
  for all to authenticated
  using (public.is_staff_mfa())
  with check (public.is_staff_mfa());

create or replace function public.create_external_threat_observation(
  p_canonical_url text,
  p_source_name text,
  p_source_url text,
  p_expires_at timestamptz
) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  if not public.is_staff_mfa() then raise exception 'Complete MFA before recording an external threat observation'; end if;
  if trim(coalesce(p_canonical_url, '')) !~ '^https?://' then raise exception 'A canonical HTTP or HTTPS URL is required'; end if;
  if char_length(trim(coalesce(p_source_name, ''))) < 2 or trim(coalesce(p_source_url, '')) !~ '^https://' then raise exception 'A named HTTPS source is required'; end if;
  if p_expires_at is null or p_expires_at <= now() then raise exception 'Use a future expiry date'; end if;
  insert into public.external_threat_observations (canonical_url, source_name, source_url, evidence_status, expires_at, created_by)
  values (trim(p_canonical_url), trim(p_source_name), trim(p_source_url), 'reported', p_expires_at, auth.uid())
  on conflict (canonical_url) do update set source_name = excluded.source_name, source_url = excluded.source_url, evidence_status = 'reported', expires_at = excluded.expires_at, created_by = auth.uid(), created_at = now()
  returning id into v_id;
  insert into public.audit_logs (actor_id, action, resource_type, resource_id, metadata)
  values (auth.uid(), 'external_threat_reported', 'external_threat_observation', v_id::text, jsonb_build_object('source_name', trim(p_source_name)));
  return v_id;
end;
$$;
revoke all on function public.create_external_threat_observation(text, text, text, timestamptz) from public;
grant execute on function public.create_external_threat_observation(text, text, text, timestamptz) to authenticated;
