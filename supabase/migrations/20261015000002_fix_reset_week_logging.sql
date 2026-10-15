create or replace function public.reset_week(p_password text)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public, private, extensions
as $$
declare
  stored_hash text;
  member_record record;
  reset_members integer := 0;
begin
  select password_hash into stored_hash
  from private.reset_settings
  where singleton = true;

  if stored_hash is null or p_password is null or extensions.crypt(p_password, stored_hash) <> stored_hash then
    raise exception 'Invalid reset password.' using errcode = '42501';
  end if;

  for member_record in
    select id, points
    from public.members
    where points > 0
    for update
  loop
    update public.members
    set points = 0
    where id = member_record.id;

    insert into public.point_log (member_id, amount)
    values (member_record.id, -member_record.points);

    reset_members := reset_members + 1;
  end loop;

  return reset_members;
end;
$$;

revoke all on function public.reset_week(text) from public;
grant execute on function public.reset_week(text) to anon, authenticated;