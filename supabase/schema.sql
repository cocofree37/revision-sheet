-- 修正依頼シート : Supabase スキーマ
-- Supabase の SQL Editor に貼り付けて実行してください（再実行しても壊れません）。
--
-- 方針
--  * テーブルは RLS を有効にし、ポリシーを1つも作らない → 公開キー(anon)ではテーブルに直接触れない
--  * 公開するのは下の関数だけ。各関数が「案件キー」を確認してから処理する
--  * 案件キーは2種類：client_key（クライアント用）/ admin_key（制作用）
--  * 案件の作成・キー一覧は「マスターキー」が必要

-- ★ 実行前に、下の '__MASTER_KEY__' を推測されにくい長い文字列（16文字以上）に置き換えてください。
do $$
begin
  if '__MASTER_KEY__' = '__' || 'MASTER_KEY__' then
    raise exception 'マスターキーを設定してください（__MASTER_KEY__ を置き換える）';
  end if;
end $$;

-- ---------------------------------------------------------------- テーブル
create table if not exists public.projects (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (char_length(name) between 1 and 80),
  site_url    text not null default '' check (char_length(site_url) <= 300),
  client_key  text not null unique,
  admin_key   text not null unique,
  created_at  timestamptz not null default now()
);

create table if not exists public.issues (
  id          bigint generated always as identity primary key,
  project_id  uuid not null references public.projects(id) on delete cascade,
  no          int  not null,
  title       text not null check (char_length(title) between 1 and 120),
  page_url    text not null default '' check (char_length(page_url) <= 300),
  detail      text not null default '' check (char_length(detail) <= 3000),
  category    text not null default 'その他'
              check (category in ('デザイン','文言・テキスト','画像・写真','機能・動作','その他')),
  priority    text not null default '中' check (priority in ('高','中','低')),
  status      text not null default '未対応'
              check (status in ('未対応','対応中','確認待ち','完了','保留')),
  reporter    text not null default '' check (char_length(reporter) <= 40),
  assignee    text not null default '' check (char_length(assignee) <= 40),
  images      jsonb not null default '[]'::jsonb,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (project_id, no)
);

create table if not exists public.comments (
  id          bigint generated always as identity primary key,
  issue_id    bigint not null references public.issues(id) on delete cascade,
  author      text not null default '' check (char_length(author) <= 40),
  role        text not null check (role in ('client','admin')),
  body        text not null default '' check (char_length(body) <= 2000),
  images      jsonb not null default '[]'::jsonb,
  created_at  timestamptz not null default now()
);

create table if not exists public.app_config (
  k text primary key,
  v text not null
);

create index if not exists comments_issue_idx on public.comments(issue_id);

-- ---------------------------------------------------------------- アクセス制限
alter table public.projects   enable row level security;
alter table public.issues     enable row level security;
alter table public.comments   enable row level security;
alter table public.app_config enable row level security;

revoke all on public.projects, public.issues, public.comments, public.app_config
  from anon, authenticated;

-- ---------------------------------------------------------------- マスターキー
insert into public.app_config (k, v) values ('master_key', '__MASTER_KEY__')
on conflict (k) do update set v = excluded.v;

-- ---------------------------------------------------------------- 内部ヘルパー（外部には公開しない）
create or replace function public._who(p_key text)
returns table(project_id uuid, role text)
language sql stable security definer set search_path = public, pg_temp as $$
  select id, 'admin'::text  from projects where admin_key  = p_key
  union all
  select id, 'client'::text from projects where client_key = p_key
  limit 1;
$$;

create or replace function public._master_ok(p text)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select length(coalesce(p, '')) >= 12
     and exists (select 1 from app_config where k = 'master_key' and v = p);
$$;

create or replace function public._check_images(p jsonb)
returns jsonb
language plpgsql immutable set search_path = public, pg_temp as $$
declare e jsonb;
begin
  if p is null or p = 'null'::jsonb then return '[]'::jsonb; end if;
  if jsonb_typeof(p) <> 'array' or jsonb_array_length(p) > 5 then
    raise exception 'invalid_images';
  end if;
  for e in select * from jsonb_array_elements(p) loop
    if jsonb_typeof(e) <> 'string'
       or (e #>> '{}') !~ '^data:image/(jpeg|png|webp|gif);base64,'
       or length(e #>> '{}') > 320000 then
      raise exception 'invalid_images';
    end if;
  end loop;
  return p;
end $$;

create or replace function public._new_key()
returns text
language sql volatile set search_path = public, pg_temp as $$
  select replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
$$;

-- ---------------------------------------------------------------- 案件キーで使う関数
create or replace function public.get_project(p_key text)
returns jsonb
language plpgsql stable security definer set search_path = public, pg_temp as $$
declare w record; r jsonb;
begin
  select * into w from _who(p_key);
  if not found then raise exception 'invalid_key'; end if;
  select jsonb_build_object('name', name, 'site_url', site_url, 'role', w.role)
    into r from projects where id = w.project_id;
  return r;
end $$;

create or replace function public.list_issues(p_key text)
returns jsonb
language plpgsql stable security definer set search_path = public, pg_temp as $$
declare w record;
begin
  select * into w from _who(p_key);
  if not found then raise exception 'invalid_key'; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'no', i.no, 'title', i.title, 'page_url', i.page_url,
      'category', i.category, 'priority', i.priority, 'status', i.status,
      'reporter', i.reporter, 'assignee', i.assignee,
      'created_at', i.created_at, 'updated_at', i.updated_at,
      'comment_count', (select count(*) from comments c where c.issue_id = i.id),
      'image_count', jsonb_array_length(i.images)
    ) order by i.no desc)
    from issues i where i.project_id = w.project_id
  ), '[]'::jsonb);
end $$;

create or replace function public.get_issue(p_key text, p_no int)
returns jsonb
language plpgsql stable security definer set search_path = public, pg_temp as $$
declare w record; i issues%rowtype;
begin
  select * into w from _who(p_key);
  if not found then raise exception 'invalid_key'; end if;
  select * into i from issues where project_id = w.project_id and no = p_no;
  if not found then raise exception 'not_found'; end if;
  return (to_jsonb(i) - 'id' - 'project_id')
    || jsonb_build_object('comments', coalesce((
         select jsonb_agg(jsonb_build_object(
           'id', c.id, 'author', c.author, 'role', c.role, 'body', c.body,
           'images', c.images, 'created_at', c.created_at) order by c.id)
         from comments c where c.issue_id = i.id
       ), '[]'::jsonb));
end $$;

create or replace function public.add_issue(
  p_key text, p_title text, p_page_url text, p_detail text,
  p_category text, p_priority text, p_reporter text, p_images jsonb)
returns int
language plpgsql security definer set search_path = public, pg_temp as $$
declare w record; n int; imgs jsonb; t text;
begin
  select * into w from _who(p_key);
  if not found then raise exception 'invalid_key'; end if;
  imgs := _check_images(p_images);
  t := left(btrim(coalesce(p_title, '')), 120);
  if t = '' then t := '（内容を確認）'; end if;
  if coalesce(p_category, '') not in ('デザイン','文言・テキスト','画像・写真','機能・動作','その他') then
    p_category := 'その他';
  end if;
  if coalesce(p_priority, '') not in ('高','中','低') then p_priority := '中'; end if;
  perform pg_advisory_xact_lock(hashtext(w.project_id::text));
  select coalesce(max(no), 0) + 1 into n from issues where project_id = w.project_id;
  insert into issues (project_id, no, title, page_url, detail, category, priority, reporter, images)
  values (w.project_id, n, t, left(coalesce(p_page_url, ''), 300), left(coalesce(p_detail, ''), 3000),
          p_category, p_priority, left(coalesce(p_reporter, ''), 40), imgs);
  return n;
end $$;

create or replace function public.add_comment(
  p_key text, p_no int, p_author text, p_body text, p_images jsonb)
returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare w record; iid bigint; imgs jsonb; b text;
begin
  select * into w from _who(p_key);
  if not found then raise exception 'invalid_key'; end if;
  select id into iid from issues where project_id = w.project_id and no = p_no;
  if not found then raise exception 'not_found'; end if;
  imgs := _check_images(p_images);
  b := left(btrim(coalesce(p_body, '')), 2000);
  if b = '' and jsonb_array_length(imgs) = 0 then raise exception 'empty'; end if;
  insert into comments (issue_id, author, role, body, images)
  values (iid, left(coalesce(p_author, ''), 40), w.role, b, imgs);
  update issues set updated_at = now() where id = iid;
end $$;

create or replace function public.update_issue(p_key text, p_no int, p_patch jsonb)
returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare w record; i issues%rowtype; s text;
begin
  select * into w from _who(p_key);
  if not found then raise exception 'invalid_key'; end if;
  select * into i from issues where project_id = w.project_id and no = p_no;
  if not found then raise exception 'not_found'; end if;
  if w.role = 'admin' then
    update issues set
      title     = coalesce(nullif(left(btrim(p_patch->>'title'), 120), ''), title),
      status    = coalesce(p_patch->>'status', status),
      priority  = coalesce(p_patch->>'priority', priority),
      category  = coalesce(p_patch->>'category', category),
      assignee  = left(coalesce(p_patch->>'assignee', assignee), 40),
      updated_at = now()
    where id = i.id;
  else
    -- クライアントができるのは「確認待ち」の依頼を 完了 / 差し戻し にすることだけ
    s := p_patch->>'status';
    if i.status = '確認待ち' and s in ('完了','未対応')
       and (select count(*) from jsonb_object_keys(p_patch)) = 1 then
      update issues set status = s, updated_at = now() where id = i.id;
    else
      raise exception 'forbidden';
    end if;
  end if;
end $$;

create or replace function public.delete_issue(p_key text, p_no int)
returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare w record;
begin
  select * into w from _who(p_key);
  if not found then raise exception 'invalid_key'; end if;
  if w.role <> 'admin' then raise exception 'forbidden'; end if;
  delete from issues where project_id = w.project_id and no = p_no;
end $$;

create or replace function public.update_project(p_key text, p_name text, p_site_url text)
returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare w record;
begin
  select * into w from _who(p_key);
  if not found then raise exception 'invalid_key'; end if;
  if w.role <> 'admin' then raise exception 'forbidden'; end if;
  update projects set
    name = coalesce(nullif(left(btrim(p_name), 80), ''), name),
    site_url = left(coalesce(btrim(p_site_url), ''), 300)
  where id = w.project_id;
end $$;

-- ---------------------------------------------------------------- マスターキーで使う関数
create or replace function public.create_project(p_master text, p_name text, p_site_url text)
returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare r projects%rowtype; n text;
begin
  if not _master_ok(p_master) then raise exception 'forbidden'; end if;
  n := left(btrim(coalesce(p_name, '')), 80);
  if n = '' then raise exception 'invalid'; end if;
  insert into projects (name, site_url, client_key, admin_key)
  values (n, left(coalesce(btrim(p_site_url), ''), 300), _new_key(), _new_key())
  returning * into r;
  return jsonb_build_object('id', r.id, 'client_key', r.client_key, 'admin_key', r.admin_key);
end $$;

create or replace function public.list_projects(p_master text)
returns jsonb
language plpgsql stable security definer set search_path = public, pg_temp as $$
begin
  if not _master_ok(p_master) then raise exception 'forbidden'; end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id', p.id, 'name', p.name, 'site_url', p.site_url,
      'client_key', p.client_key, 'admin_key', p.admin_key, 'created_at', p.created_at,
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
  if not _master_ok(p_master) then raise exception 'forbidden'; end if;
  update projects set client_key = _new_key(), admin_key = _new_key()
  where id = p_id returning * into r;
  if not found then raise exception 'not_found'; end if;
  return jsonb_build_object('client_key', r.client_key, 'admin_key', r.admin_key);
end $$;

-- ---------------------------------------------------------------- 関数の公開範囲
-- いったん全部の関数の実行権限を外し、必要な関数だけ anon（公開キー）に許可する
revoke execute on all functions in schema public from public, anon, authenticated;

grant execute on function
  public.get_project(text),
  public.list_issues(text),
  public.get_issue(text, int),
  public.add_issue(text, text, text, text, text, text, text, jsonb),
  public.add_comment(text, int, text, text, jsonb),
  public.update_issue(text, int, jsonb),
  public.delete_issue(text, int),
  public.update_project(text, text, text),
  public.create_project(text, text, text),
  public.list_projects(text),
  public.regenerate_keys(text, uuid)
to anon;
