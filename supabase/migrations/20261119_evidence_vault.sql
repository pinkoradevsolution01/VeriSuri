-- Private, owner-only evidence vault. Upload only redacted evidence.
create table if not exists public.evidence_vault_items (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  item_type text not null check (item_type in ('screenshot', 'transaction_reference', 'note')),
  storage_path text unique,
  filename text,
  transaction_reference text,
  occurred_at timestamptz,
  note text,
  created_at timestamptz not null default now()
);
alter table public.evidence_vault_items enable row level security;
create policy "own_evidence_vault_items" on public.evidence_vault_items for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('evidence-vault', 'evidence-vault', false, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = false, file_size_limit = 5242880, allowed_mime_types = array['image/jpeg','image/png','image/webp'];

create policy "own_evidence_vault_uploads" on storage.objects for insert to authenticated
with check (bucket_id = 'evidence-vault' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "own_evidence_vault_reads" on storage.objects for select to authenticated
using (bucket_id = 'evidence-vault' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "own_evidence_vault_deletes" on storage.objects for delete to authenticated
using (bucket_id = 'evidence-vault' and (storage.foldername(name))[1] = auth.uid()::text);
