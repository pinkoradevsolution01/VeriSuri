-- Subscription state and server-enforced Web Risk scan quotas.
-- Run after 20261116_production_readiness.sql.

alter table public.profiles
  add column if not exists subscription_plan text not null default 'free'
    check (subscription_plan in ('free', 'pro', 'premium')),
  add column if not exists subscription_status text not null default 'active'
    check (subscription_status in ('active', 'pending_payment', 'cancelled')),
  add column if not exists pending_plan text
    check (pending_plan is null or pending_plan in ('pro', 'premium'));

create table if not exists public.web_risk_monthly_usage (
  period_start date primary key,
  free_lookups integer not null default 0 check (free_lookups >= 0),
  pro_lookups integer not null default 0 check (pro_lookups >= 0),
  premium_lookups integer not null default 0 check (premium_lookups >= 0),
  updated_at timestamptz not null default now()
);

create table if not exists public.web_risk_daily_usage (
  user_id uuid not null references auth.users(id) on delete cascade,
  usage_date date not null,
  lookups integer not null default 0 check (lookups >= 0),
  primary key (user_id, usage_date)
);

alter table public.web_risk_monthly_usage enable row level security;
alter table public.web_risk_daily_usage enable row level security;

-- Users can view their own plan; only a trusted payment webhook/service role can activate paid plans.
create policy "own_web_risk_daily_usage" on public.web_risk_daily_usage for select using (user_id = auth.uid());
create policy "staff_web_risk_usage" on public.web_risk_daily_usage for select using (public.is_staff());
create policy "staff_web_risk_monthly_usage" on public.web_risk_monthly_usage for select using (public.is_staff());

create or replace function public.select_subscription_plan(p_plan text)
returns table (subscription_plan text, subscription_status text, pending_plan text)
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Sign in is required'; end if;
  if p_plan not in ('free', 'pro', 'premium') then raise exception 'Invalid subscription plan'; end if;

  if p_plan = 'free' then
    update public.profiles
    set subscription_plan = 'free', subscription_status = 'active', pending_plan = null, updated_at = now()
    where id = auth.uid();
  else
    -- A browser can request a paid plan but cannot activate it. Activation must be
    -- performed only by a verified payment webhook using the service role.
    update public.profiles
    set subscription_status = 'pending_payment', pending_plan = p_plan, updated_at = now()
    where id = auth.uid();
  end if;

  return query select p.subscription_plan, p.subscription_status, p.pending_plan from public.profiles p where p.id = auth.uid();
end;
$$;

-- Atomically reserves one Google Web Risk lookup. Dates use Philippine time.
-- Free accounts share a 100,000-request monthly allocation. The daily free limit
-- is recalculated on every call as min(15, remaining allocation / active users / days left).
-- Paid plans have fixed daily limits after a verified payment activation.
create or replace function public.consume_web_risk_quota(p_user_id uuid, p_free_monthly_budget integer default 100000)
returns table (allowed boolean, plan text, daily_limit integer, used_today integer, remaining_today integer, reason text)
language plpgsql security definer set search_path = public as $$
declare
  v_today date := (now() at time zone 'Asia/Manila')::date;
  v_period date := date_trunc('month', (now() at time zone 'Asia/Manila'))::date;
  v_days_left integer := ((date_trunc('month', (now() at time zone 'Asia/Manila')) + interval '1 month - 1 day')::date - v_today + 1);
  v_plan text;
  v_status text;
  v_active_free integer;
  v_month_free integer;
  v_used integer;
  v_limit integer;
begin
  if p_free_monthly_budget < 0 then raise exception 'Invalid monthly budget'; end if;
  select subscription_plan, subscription_status into v_plan, v_status from public.profiles where id = p_user_id;
  if not found then
    return query select false, 'free'::text, 0, 0, 0, 'No subscription profile found';
    return;
  end if;
  if v_plan in ('pro', 'premium') and v_status <> 'active' then
    return query select false, v_plan, 0, 0, 0, 'Paid plan is awaiting verified payment';
    return;
  end if;

  insert into public.web_risk_monthly_usage(period_start) values (v_period) on conflict (period_start) do nothing;
  -- The monthly row lock prevents concurrent free users from exceeding the allocation.
  select free_lookups into v_month_free from public.web_risk_monthly_usage where period_start = v_period for update;
  select lookups into v_used from public.web_risk_daily_usage where user_id = p_user_id and usage_date = v_today;
  v_used := coalesce(v_used, 0);

  if v_plan = 'free' then
    select count(*) into v_active_free from public.profiles where subscription_plan = 'free' and subscription_status = 'active';
    v_limit := least(15, floor(greatest(p_free_monthly_budget - v_month_free, 0)::numeric / greatest(v_active_free, 1) / greatest(v_days_left, 1))::integer);
    if v_month_free >= p_free_monthly_budget then
      return query select false, v_plan, v_limit, v_used, greatest(v_limit - v_used, 0), 'The shared free Web Risk allocation is exhausted for this month';
      return;
    end if;
  elsif v_plan = 'pro' then
    v_limit := 30;
  else
    v_limit := 100;
  end if;

  if v_used >= v_limit then
    return query select false, v_plan, v_limit, v_used, 0, 'Daily URL-scan limit reached';
    return;
  end if;

  insert into public.web_risk_daily_usage(user_id, usage_date, lookups) values (p_user_id, v_today, 1)
  on conflict (user_id, usage_date) do update set lookups = public.web_risk_daily_usage.lookups + 1;
  if v_plan = 'free' then
    update public.web_risk_monthly_usage set free_lookups = free_lookups + 1, updated_at = now() where period_start = v_period;
  elsif v_plan = 'pro' then
    update public.web_risk_monthly_usage set pro_lookups = pro_lookups + 1, updated_at = now() where period_start = v_period;
  else
    update public.web_risk_monthly_usage set premium_lookups = premium_lookups + 1, updated_at = now() where period_start = v_period;
  end if;
  return query select true, v_plan, v_limit, v_used + 1, greatest(v_limit - v_used - 1, 0), 'Google Web Risk lookup reserved';
end;
$$;

revoke all on function public.select_subscription_plan(text) from public;
grant execute on function public.select_subscription_plan(text) to authenticated;
revoke all on function public.consume_web_risk_quota(uuid, integer) from public;
grant execute on function public.consume_web_risk_quota(uuid, integer) to service_role;
