-- Public-facing codenames are separate from OAuth/display names.
alter table public.profiles add column if not exists codename text;
create unique index if not exists profiles_codename_unique_idx
  on public.profiles (lower(codename)) where codename is not null;

create or replace function public.set_profile_codename(p_codename text)
returns text language plpgsql security definer set search_path = public as $$
declare v_codename text := trim(coalesce(p_codename, ''));
begin
  if auth.uid() is null then raise exception 'Sign in is required'; end if;
  if v_codename !~ '^[A-Za-z0-9][A-Za-z0-9 _-]{2,29}$' then
    raise exception 'Use 3–30 letters, numbers, spaces, hyphens, or underscores.';
  end if;
  update public.profiles set codename = v_codename, updated_at = now() where id = auth.uid();
  -- Keep already published, opted-in contributor acknowledgements current.
  update public.scam_reports set public_contributor_name = v_codename
  where reporter_id = auth.uid() and public_contributor_opt_in = true and status = 'confirmed';
  return v_codename;
end;
$$;

revoke all on function public.set_profile_codename(text) from public;
grant execute on function public.set_profile_codename(text) to authenticated;
