-- Create a limited in-app advisory only after a moderator confirms a report.
-- It contains no reporter identity, identifier, URL, account number, narrative, or evidence.

alter table public.fraud_alerts
  add column if not exists source_report_id uuid unique references public.scam_reports(id) on delete cascade;

create or replace function public.publish_confirmed_report_alert()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_type text := coalesce(nullif(replace(new.scam_type, '_', ' '), ''), 'scam');
  v_channel text := coalesce(nullif(replace(new.incident_channel, '_', ' '), ''), 'digital channel');
  v_platform text := coalesce(nullif(replace(new.payment_provider, '_', ' '), ''), 'community report');
begin
  if new.status = 'confirmed' and old.status is distinct from new.status then
    insert into public.fraud_alerts (
      title, summary, severity, status, published, published_at,
      source_name, source_url, affected_platform, region,
      review_at, expires_at, reviewed_by, reviewed_at, source_report_id
    ) values (
      'New verified community scam report',
      'A moderator confirmed a ' || v_type || ' report received through ' || v_channel || '. Verify unexpected requests independently through an official channel.',
      'medium', 'verified', true, now(),
      'VeriSuri moderator review', 'https://veri-suri.vercel.app/#/contributors', v_platform, 'Nationwide',
      now() + interval '7 days', now() + interval '30 days', new.reviewed_by, now(), new.id
    ) on conflict (source_report_id) do nothing;
  end if;
  return new;
end;
$$;

drop trigger if exists publish_confirmed_report_alert on public.scam_reports;
create trigger publish_confirmed_report_alert
after update of status on public.scam_reports
for each row execute procedure public.publish_confirmed_report_alert();

-- Create advisories for reports confirmed before the trigger was installed.
insert into public.fraud_alerts (
  title, summary, severity, status, published, published_at,
  source_name, source_url, affected_platform, region,
  review_at, expires_at, reviewed_by, reviewed_at, source_report_id
)
select
  'New verified community scam report',
  'A moderator confirmed a ' || coalesce(nullif(replace(r.scam_type, '_', ' '), ''), 'scam') || ' report received through ' || coalesce(nullif(replace(r.incident_channel, '_', ' '), ''), 'digital channel') || '. Verify unexpected requests independently through an official channel.',
  'medium', 'verified', true, now(),
  'VeriSuri moderator review', 'https://veri-suri.vercel.app/#/contributors', coalesce(nullif(replace(r.payment_provider, '_', ' '), ''), 'community report'), 'Nationwide',
  now() + interval '7 days', now() + interval '30 days', r.reviewed_by, now(), r.id
from public.scam_reports r
where r.status = 'confirmed'
on conflict (source_report_id) do nothing;
