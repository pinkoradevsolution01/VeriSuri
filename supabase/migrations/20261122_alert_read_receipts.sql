-- Per-member in-app notification read state for verified safety alerts.
-- This intentionally tracks only published, moderator-verified advisories.

create table if not exists public.alert_reads (
  user_id uuid not null references auth.users(id) on delete cascade,
  alert_id uuid not null references public.fraud_alerts(id) on delete cascade,
  read_at timestamptz not null default now(),
  primary key (user_id, alert_id)
);

create index if not exists alert_reads_user_read_idx
  on public.alert_reads (user_id, read_at desc);

alter table public.alert_reads enable row level security;

drop policy if exists "own_alert_reads" on public.alert_reads;
create policy "own_alert_reads" on public.alert_reads
  for all to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());
