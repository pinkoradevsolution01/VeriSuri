-- Ensures every authenticated account can activate and persist the Free plan.
-- Run this after the existing subscription migration.

alter table public.profiles
  add column if not exists subscription_plan text not null default 'free'
    check (subscription_plan in ('free', 'pro', 'premium')),
  add column if not exists subscription_status text not null default 'active'
    check (subscription_status in ('active', 'pending_payment', 'cancelled')),
  add column if not exists pending_plan text
    check (pending_plan is null or pending_plan in ('pro', 'premium'));

create or replace function public.select_subscription_plan(p_plan text)
returns table (subscription_plan text, subscription_status text, pending_plan text)
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then
    raise exception 'Sign in is required';
  end if;
  if p_plan not in ('free', 'pro', 'premium') then
    raise exception 'Invalid subscription plan';
  end if;

  -- A profile may be absent for an account created before the profile trigger.
  -- The signed-in account can always initialize its own Free subscription.
  insert into public.profiles (id)
  values (auth.uid())
  on conflict (id) do nothing;

  if p_plan = 'free' then
    update public.profiles
    set subscription_plan = 'free', subscription_status = 'active', pending_plan = null, updated_at = now()
    where id = auth.uid();
  else
    -- Paid plan activation stays server-controlled after verified payment.
    update public.profiles
    set subscription_status = 'pending_payment', pending_plan = p_plan, updated_at = now()
    where id = auth.uid();
  end if;

  return query
  select p.subscription_plan, p.subscription_status, p.pending_plan
  from public.profiles p
  where p.id = auth.uid();
end;
$$;

revoke all on function public.select_subscription_plan(text) from public;
grant execute on function public.select_subscription_plan(text) to authenticated;
