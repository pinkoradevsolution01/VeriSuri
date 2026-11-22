-- Publish a restricted contributor acknowledgement automatically after moderation.
-- This never publishes a raw identifier, narrative, evidence, email, or account number.

alter table public.profiles add column if not exists codename text;
alter table public.scam_reports
  add column if not exists public_contributor_opt_in boolean not null default false,
  add column if not exists public_contributor_name text,
  add column if not exists public_reference text;

create or replace function public.hydrate_confirmed_contributor()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_codename text;
  v_entity_type text;
  v_last4 text;
begin
  if new.status = 'confirmed' and old.status is distinct from new.status then
    select coalesce(nullif(trim(codename), ''), 'Verified contributor') into v_codename
    from public.profiles where id = new.reporter_id;
    select entity_type::text, entity_last4 into v_entity_type, v_last4
    from public.reported_entities where report_id = new.id order by created_at asc limit 1;

    new.public_contributor_opt_in := true;
    new.public_contributor_name := coalesce(v_codename, 'Verified contributor');
    new.public_reference := case
      when v_entity_type is null then 'Redacted report reference'
      when coalesce(v_last4, '') = '' then initcap(replace(v_entity_type, '_', ' ')) || ' (redacted)'
      else initcap(replace(v_entity_type, '_', ' ')) || ' ending ' || v_last4
    end;
  end if;
  return new;
end;
$$;

drop trigger if exists populate_confirmed_contributor on public.scam_reports;
create trigger populate_confirmed_contributor
before update of status on public.scam_reports
for each row execute procedure public.hydrate_confirmed_contributor();

-- Backfill records confirmed before this trigger was installed.
update public.scam_reports r
set public_contributor_opt_in = true,
    public_contributor_name = coalesce(nullif(trim(p.codename), ''), 'Verified contributor'),
    public_reference = coalesce((
      select case
        when coalesce(e.entity_last4, '') = '' then initcap(replace(e.entity_type::text, '_', ' ')) || ' (redacted)'
        else initcap(replace(e.entity_type::text, '_', ' ')) || ' ending ' || e.entity_last4
      end
      from public.reported_entities e where e.report_id = r.id order by e.created_at asc limit 1
    ), 'Redacted report reference')
from public.profiles p
where r.reporter_id = p.id and r.status = 'confirmed'
  and (not r.public_contributor_opt_in or r.public_contributor_name is null or r.public_reference is null);
