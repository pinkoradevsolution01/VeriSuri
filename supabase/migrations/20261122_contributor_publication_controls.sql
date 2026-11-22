-- Public contributor acknowledgements: codename plus a limited, inert reference only.
-- Run after the existing VeriSuri migrations.

alter table public.profiles add column if not exists codename text;
alter table public.scam_reports
  add column if not exists public_contributor_opt_in boolean not null default false,
  add column if not exists public_contributor_name text,
  add column if not exists public_reference text;

create index if not exists scam_reports_public_contributors_idx
  on public.scam_reports (created_at desc)
  where status = 'confirmed' and public_contributor_opt_in = true;

create or replace function public.set_report_contributor_visibility(
  p_report_id uuid,
  p_visible boolean
) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_codename text;
  v_entity_type text;
  v_last4 text;
begin
  if auth.uid() is null then raise exception 'Sign in is required'; end if;

  if not exists (
    select 1 from public.scam_reports
    where id = p_report_id and reporter_id = auth.uid() and status = 'confirmed'
  ) then
    raise exception 'Only your moderator-confirmed report can be shared in Contributors';
  end if;

  if not p_visible then
    update public.scam_reports
    set public_contributor_opt_in = false, public_contributor_name = null, public_reference = null
    where id = p_report_id and reporter_id = auth.uid();
    return;
  end if;

  select trim(coalesce(codename, '')) into v_codename
  from public.profiles where id = auth.uid();
  if char_length(v_codename) < 3 then
    raise exception 'Choose a VeriSuri codename in Account Security before sharing a contribution';
  end if;

  select entity_type::text, entity_last4 into v_entity_type, v_last4
  from public.reported_entities where report_id = p_report_id
  order by created_at asc limit 1;

  update public.scam_reports
  set public_contributor_opt_in = true,
      public_contributor_name = v_codename,
      public_reference = case
        when v_entity_type is null then 'Redacted report reference'
        when coalesce(v_last4, '') = '' then initcap(replace(v_entity_type, '_', ' ')) || ' (redacted)'
        else initcap(replace(v_entity_type, '_', ' ')) || ' ending ' || v_last4
      end
  where id = p_report_id and reporter_id = auth.uid();
end;
$$;

revoke all on function public.set_report_contributor_visibility(uuid, boolean) from public;
grant execute on function public.set_report_contributor_visibility(uuid, boolean) to authenticated;
