-- 002: Email認証（クライアントの入場制限 + 制作チームのログイン）
-- Supabase の SQL Editor で実行してください（再実行しても壊れません）。
--
-- 仕組み
--  * ログインは Supabase Auth のメール認証コード（6桁）。ログインすると JWT にメールアドレスが入る
--  * staff（制作チーム）に登録されたメールでログインした人は、全案件を「制作チーム」として操作できる
--  * 案件ごとに access を選べる
--      open  : 案件キーを知っていれば入れる（これまでどおり）
--      email : 案件キーに加えて、許可したメールアドレスでログインした人だけが入れる
--  * 案件の作成・キー一覧などは、マスターキー または staff のログインで行う

-- ---------------------------------------------------------------- テーブル
create table if not exists public.staff (
  email text primary key check (email = lower(email) and char_length(email) between 3 and 200)
);

create table if not exists public.project_members (
  project_id uuid not null references public.projects(id) on delete cascade,
  email      text not null check (email = lower(email) and char_length(email) between 3 and 200),
  primary key (project_id, email)
);

alter table public.projects add column if not exists access text not null default 'open';
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'projects_access_check') then
    alter table public.projects add constraint projects_access_check check (access in ('open', 'email'));
  end if;
end $$;

alter table public.staff           enable row level security;
alter table public.project_members enable row level security;
revoke all on public.staff, public.project_members from anon, authenticated;

-- ---------------------------------------------------------------- ヘルパー（外部には公開しない）
create or replace function public._email()
returns text
language sql stable set search_path = public, pg_temp as $$
  select lower(coalesce(auth.jwt() ->> 'email', ''));
$$;

create or replace function public._is_staff()
returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select _email() <> '' and exists (select 1 from staff where email = _email());
$$;

-- マスターキー または staff のログイン
create or replace function public._is_manager(p_master text)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select _master_ok(p_master) or _is_staff();
$$;

-- 案件キー + ログイン状態から、案件と役割を決める
create or replace function public._who(p_key text)
returns table(project_id uuid, role text)
language plpgsql stable security definer set search_path = public, pg_temp as $$
declare pr projects%rowtype; em text := _email(); base text;
begin
  select * into pr from projects where client_key = p_key or admin_key = p_key limit 1;
  if not found then return; end if;
  base := case when pr.admin_key = p_key then 'admin' else 'client' end;

  -- 制作チーム（staff）でログイン中なら、どの案件でも制作チーム
  if em <> '' and exists (select 1 from staff s where s.email = em) then
    project_id := pr.id; role := 'admin'; return next; return;
  end if;

  -- キーだけで入れる案件
  if pr.access = 'open' then
    project_id := pr.id; role := base; return next; return;
  end if;

  -- メール認証が必要な案件
  if em = '' then raise exception 'auth_required'; end if;
  if exists (select 1 from project_members m where m.project_id = pr.id and m.email = em) then
    project_id := pr.id; role := 'client'; return next; return;
  end if;
  raise exception 'not_allowed';
end $$;

-- ---------------------------------------------------------------- ログイン状態の確認
create or replace function public.get_me()
returns jsonb
language sql stable security definer set search_path = public, pg_temp as $$
  select jsonb_build_object('email', nullif(_email(), ''), 'is_staff', _is_staff());
$$;

-- ---------------------------------------------------------------- 案件の管理（マスターキー or staff）
create or replace function public.create_project(p_master text, p_name text, p_site_url text)
returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare r projects%rowtype; n text;
begin
  if not _is_manager(p_master) then raise exception 'forbidden'; end if;
  n := left(btrim(coalesce(p_name, '')), 80);
  if n = '' then raise exception 'invalid'; end if;
  insert into projects (name, site_url, client_key, admin_key, access)
  values (n, left(coalesce(btrim(p_site_url), ''), 300), _new_key(), _new_key(), 'email')
  returning * into r;
  return jsonb_build_object('id', r.id, 'client_key', r.client_key, 'admin_key', r.admin_key);
end $$;

create or replace function public.list_projects(p_master text)
returns jsonb
language plpgsql stable security definer set search_path = public, pg_temp as $$
begin
  if not _is_manager(p_master) then raise exception 'forbidden'; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id', p.id, 'name', p.name, 'site_url', p.site_url,
      'client_key', p.client_key, 'admin_key', p.admin_key, 'created_at', p.created_at,
      'access', p.access,
      'members', coalesce((select jsonb_agg(m.email order by m.email) from project_members m where m.project_id = p.id), '[]'::jsonb),
      'total', (select count(*) from issues i where i.project_id = p.id),
      'open',  (select count(*) from issues i where i.project_id = p.id and i.status not in ('完了','保留'))
    ) order by p.created_at desc)
    from projects p
  ), '[]'::jsonb);
end $$;

create or replace function public.regenerate_keys(p_master text, p_id uuid)
returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare r projects%rowtype;
begin
  if not _is_manager(p_master) then raise exception 'forbidden'; end if;
  update projects set client_key = _new_key(), admin_key = _new_key()
  where id = p_id returning * into r;
  if not found then raise exception 'not_found'; end if;
  return jsonb_build_object('client_key', r.client_key, 'admin_key', r.admin_key);
end $$;

-- 入場の設定：access と、許可するメールアドレス（email のときだけ使われる）
create or replace function public.set_project_access(p_master text, p_id uuid, p_access text, p_emails text[])
returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare e text; n int := 0;
begin
  if not _is_manager(p_master) then raise exception 'forbidden'; end if;
  if p_access not in ('open', 'email') then raise exception 'invalid'; end if;
  if not exists (select 1 from projects where id = p_id) then raise exception 'not_found'; end if;
  update projects set access = p_access where id = p_id;
  delete from project_members where project_id = p_id;
  foreach e in array coalesce(p_emails, '{}'::text[]) loop
    e := lower(btrim(e));
    if e = '' then continue; end if;
    if char_length(e) > 200 or e !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then
      raise exception 'invalid_email';
    end if;
    n := n + 1;
    if n > 100 then raise exception 'too_many'; end if;
    insert into project_members (project_id, email) values (p_id, e) on conflict do nothing;
  end loop;
end $$;

create or replace function public.delete_project(p_master text, p_id uuid)
returns void
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not _is_manager(p_master) then raise exception 'forbidden'; end if;
  delete from projects where id = p_id;
end $$;

-- ---------------------------------------------------------------- 制作チーム（staff）の管理
create or replace function public.list_staff(p_master text)
returns jsonb
language plpgsql stable security definer set search_path = public, pg_temp as $$
begin
  if not _is_manager(p_master) then raise exception 'forbidden'; end if;
  return coalesce((select jsonb_agg(email order by email) from staff), '[]'::jsonb);
end $$;

create or replace function public.add_staff(p_master text, p_email text)
returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare e text := lower(btrim(coalesce(p_email, '')));
begin
  if not _is_manager(p_master) then raise exception 'forbidden'; end if;
  if char_length(e) > 200 or e !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then
    raise exception 'invalid_email';
  end if;
  insert into staff (email) values (e) on conflict do nothing;
end $$;

create or replace function public.remove_staff(p_master text, p_email text)
returns void
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  if not _is_manager(p_master) then raise exception 'forbidden'; end if;
  delete from staff where email = lower(btrim(coalesce(p_email, '')));
end $$;

-- ---------------------------------------------------------------- 関数の公開範囲
-- ログイン前は anon、ログイン後は authenticated として呼ばれるため、両方に許可する
revoke execute on all functions in schema public from public, anon, authenticated;

grant execute on function
  public.get_project(text),
  public.list_issues(text, text),
  public.get_issue(text, int, text),
  public.add_issue(text, text, text, text, text, text, text, jsonb, text),
  public.add_comment(text, int, text, text, jsonb, text),
  public.update_issue(text, int, jsonb),
  public.edit_issue(text, int, text, text, text, text, jsonb),
  public.delete_issue(text, int, text),
  public.edit_comment(text, bigint, text, text, jsonb),
  public.delete_comment(text, bigint, text),
  public.update_project(text, text, text),
  public.create_project(text, text, text),
  public.list_projects(text),
  public.regenerate_keys(text, uuid),
  public.get_me(),
  public.set_project_access(text, uuid, text, text[]),
  public.delete_project(text, uuid),
  public.list_staff(text),
  public.add_staff(text, text),
  public.remove_staff(text, text)
to anon, authenticated;
