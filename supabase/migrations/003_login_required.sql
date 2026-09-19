-- 003: クライアント用URLは、ログイン必須にする
-- Supabase の SQL Editor で実行してください（再実行しても壊れません）。
--
--  access = 'open'  : 案件のURL（クライアント用）+ ログインしたメールアドレスなら誰でも入れる
--                     制作チーム用URLは、従来どおりログイン不要
--  access = 'email' : 案件のURL + 許可したメールアドレスでログインした人だけ入れる
--  staff（制作チーム）としてログインした人は、どの案件でも制作チーム

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

  if pr.access = 'open' then
    -- 制作チーム用URLは、従来どおりログイン不要
    if base = 'admin' then
      project_id := pr.id; role := 'admin'; return next; return;
    end if;
    -- クライアント用URLは、ログイン必須（メールアドレスは誰でもよい）
    if em = '' then raise exception 'auth_required'; end if;
    project_id := pr.id; role := 'client'; return next; return;
  end if;

  -- メール認証が必要な案件：許可したメールアドレスだけ
  if em = '' then raise exception 'auth_required'; end if;
  if exists (select 1 from project_members m where m.project_id = pr.id and m.email = em) then
    project_id := pr.id; role := 'client'; return next; return;
  end if;
  raise exception 'not_allowed';
end $$;
