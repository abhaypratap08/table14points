create extension if not exists pgcrypto with schema extensions;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists private.reset_settings (
  singleton boolean primary key default true check (singleton),
  password_hash text not null
);
revoke all on table private.reset_settings from public, anon, authenticated;

create or replace function public.reset_week(p_password text)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public, private, extensions
as $$
declare
  stored_hash text;
  reset_members integer;
begin
  select password_hash into stored_hash
  from private.reset_settings
  where singleton = true;

  if stored_hash is null or p_password is null or extensions.crypt(p_password, stored_hash) <> stored_hash then
    raise exception 'Invalid reset password.' using errcode = '42501';
  end if;

  with changed_members as (
    update public.members
    set points = 0
    where points > 0
    returning id, points
  )
  insert into public.point_log (member_id, amount)
  select id, -points from changed_members;

  get diagnostics reset_members = row_count;
  return reset_members;
end;
$$;

revoke all on function public.reset_week(text) from public;
grant execute on function public.reset_week(text) to anon, authenticated;