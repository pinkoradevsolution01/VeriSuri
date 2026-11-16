-- Run after 20261117_subscription_and_url_quotas.sql.
-- Stores only a one-way URL hash, not the submitted URL.
create table if not exists public.web_risk_scan_events (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  url_hash text not null,
  created_at timestamptz not null default now()
);
create index if not exists web_risk_scan_events_user_time_idx on public.web_risk_scan_events(user_id, created_at desc);
create index if not exists web_risk_scan_events_user_hash_idx on public.web_risk_scan_events(user_id, url_hash, created_at desc);
create table if not exists public.web_risk_scan_cooldowns (
  user_id uuid primary key references auth.users(id) on delete cascade,
  cooldown_until timestamptz not null,
  updated_at timestamptz not null default now()
);
alter table public.web_risk_scan_events enable row level security;
alter table public.web_risk_scan_cooldowns enable row level security;

create or replace function public.authorize_web_risk_scan(p_user_id uuid, p_url_hash text)
returns table (allowed boolean, reason text)
language plpgsql security definer set search_path = public as $$
declare
  v_cooldown timestamptz;
  v_recent_count integer;
begin
  -- Serializes decisions for a user so concurrent browser requests cannot bypass limits.
  perform pg_advisory_xact_lock(hashtext(p_user_id::text));
  select cooldown_until into v_cooldown from public.web_risk_scan_cooldowns where user_id = p_user_id;
  if v_cooldown is not null and v_cooldown > now() then
    return query select false, 'Rapid URL scanning paused Google checks for 30 minutes'; return;
  end if;
  if exists(select 1 from public.web_risk_scan_events where user_id = p_user_id and url_hash = p_url_hash and created_at > now() - interval '24 hours') then
    return query select false, 'This URL was already checked recently and did not use another scan'; return;
  end if;
  select count(*) into v_recent_count from public.web_risk_scan_events where user_id = p_user_id and created_at > now() - interval '5 minutes';
  if v_recent_count >= 3 then
    insert into public.web_risk_scan_cooldowns(user_id, cooldown_until) values (p_user_id, now() + interval '30 minutes')
    on conflict (user_id) do update set cooldown_until = excluded.cooldown_until, updated_at = now();
    return query select false, 'Rapid URL scanning paused Google checks for 30 minutes'; return;
  end if;
  insert into public.web_risk_scan_events(user_id, url_hash) values (p_user_id, p_url_hash);
  return query select true, 'URL scan authorized';
end;
$$;
revoke all on function public.authorize_web_risk_scan(uuid, text) from public;
grant execute on function public.authorize_web_risk_scan(uuid, text) to service_role;
