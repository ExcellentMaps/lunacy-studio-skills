-- ═══════════════════════════════════════════════════════════════════════
-- audit-db.sql — картина прав в базе PostgreSQL
-- Guard Security Suite © ExcellentMaps — github.com/ExcellentMaps
--
-- ЧТО ДЕЛАЕТ: показывает, кто и до чего может дотянуться.
-- ЧТО НЕ ДЕЛАЕТ: НИЧЕГО НЕ МЕНЯЕТ. Только SELECT. Безопасно запускать в бою.
--
-- ЗАПУСК:
--   psql "postgresql://ПОЛЬЗОВАТЕЛЬ@ХОСТ:5432/БАЗА" -f audit-db.sql
--   Supabase: SQL Editor -> вставить целиком -> Run
--
-- КАК ЧИТАТЬ: каждый блок заканчивается строкой «ЧТО ЗНАЧИТ».
-- Пустой результат в блоках 1-5 — это хорошо.
--
-- ГЛАВНОЕ, ЧТО НУЖНО ПОНЯТЬ ПРО РОЛИ:
--   anon          — публичный ключ. Лежит в коде сайта, виден КАЖДОМУ
--                   человеку в интернете. Всё, что можно ему, можно всем.
--   authenticated — вошедший пользователь (если используется Supabase Auth).
--   public        — «вообще все роли». Права, выданные сюда, получают все.
-- ═══════════════════════════════════════════════════════════════════════

\echo ''
\echo '═══ 1. ТАБЛИЦЫ БЕЗ ЗАЩИТЫ НА УРОВНЕ СТРОК (RLS) ═══'
\echo ''

SELECT n.nspname  AS "схема",
       c.relname  AS "таблица",
       CASE WHEN c.relrowsecurity THEN 'включена' ELSE 'ВЫКЛЮЧЕНА' END AS "RLS",
       (SELECT count(*) FROM pg_policies p
         WHERE p.schemaname = n.nspname AND p.tablename = c.relname) AS "политик"
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind = 'r'
   AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast','extensions')
   AND NOT c.relrowsecurity
 ORDER BY 1, 2;

\echo 'ЧТО ЗНАЧИТ: у этих таблиц нет защиты на уровне строк. Если до них'
\echo 'дотягивается публичный ключ (см. блок 2) — данные открыты всем.'
\echo 'ЧИНИТЬ: guard-data -> references/rls-и-права.md'
\echo ''

\echo '═══ 2. ЧТО ДОСТУПНО ПУБЛИЧНОМУ КЛЮЧУ (самое важное) ═══'
\echo ''

SELECT grantee      AS "кому",
       table_schema AS "схема",
       table_name   AS "таблица/вьюха",
       string_agg(DISTINCT privilege_type, ', ' ORDER BY privilege_type) AS "права"
  FROM information_schema.role_table_grants
 WHERE grantee IN ('anon','authenticated','PUBLIC','public')
   AND table_schema NOT IN ('pg_catalog','information_schema')
 GROUP BY 1,2,3
 ORDER BY
   CASE WHEN string_agg(privilege_type,',') LIKE '%DELETE%' THEN 1
        WHEN string_agg(privilege_type,',') LIKE '%UPDATE%' THEN 2
        WHEN string_agg(privilege_type,',') LIKE '%INSERT%' THEN 3
        ELSE 4 END,
   2, 3;

\echo 'ЧТО ЗНАЧИТ: это РЕАЛЬНАЯ поверхность атаки. Всё, что здесь у anon'
\echo 'или PUBLIC, доступно любому человеку в интернете с ключом из кода сайта.'
\echo 'DELETE и UPDATE у anon — красный уровень: базу можно стереть или подменить.'
\echo 'ПРАВИЛЬНО: этот список пустой, а доступ идёт только через функции (блок 4).'
\echo 'ЧИНИТЬ: guard-data -> examples/закрыть-права.sql'
\echo ''

\echo '═══ 3. ФУНКЦИИ SECURITY DEFINER БЕЗ ЗАКРЕПЛЁННОГО search_path ═══'
\echo ''

SELECT n.nspname AS "схема",
       p.proname AS "функция",
       pg_get_userbyid(p.proowner) AS "владелец"
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE p.prosecdef
   AND n.nspname NOT IN ('pg_catalog','information_schema','extensions')
   AND (p.proconfig IS NULL
        OR NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) cfg
                        WHERE cfg LIKE 'search\_path=%'))
 ORDER BY 1, 2;

\echo 'ЧТО ЗНАЧИТ: SECURITY DEFINER — функция работает с правами владельца базы.'
\echo 'Без закреплённого search_path злоумышленник может подсунуть свою таблицу'
\echo 'или функцию вместо настоящей, и она выполнится с полными правами.'
\echo 'Это классический способ захвата базы.'
\echo 'ЧИНИТЬ: добавить каждой: SET search_path = ваша_схема, pg_temp'
\echo ''

\echo '═══ 4. ФУНКЦИИ, КОТОРЫЕ МОЖЕТ ВЫЗВАТЬ ПУБЛИЧНЫЙ КЛЮЧ ═══'
\echo ''

SELECT r.routine_schema AS "схема",
       r.routine_name   AS "функция",
       r.grantee        AS "кому",
       CASE WHEN p.prosecdef THEN 'DEFINER (полные права)' ELSE 'INVOKER' END AS "режим"
  FROM information_schema.routine_privileges r
  LEFT JOIN pg_proc p      ON p.proname  = r.routine_name
  LEFT JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = r.routine_schema
 WHERE r.grantee IN ('anon','PUBLIC','public')
   AND r.routine_schema NOT IN ('pg_catalog','information_schema')
 ORDER BY 1, 2;

\echo 'ЧТО ЗНАЧИТ: это единственная законная дверь в базу. Здесь должны быть'
\echo 'ТОЛЬКО те функции, которые вы осознанно открыли, и каждая из них обязана'
\echo 'сама проверять, кто её вызвал и что этому человеку положено.'
\echo 'Любая лишняя строка здесь — дыра. Сверьте список со своим кодом.'
\echo ''

\echo '═══ 5. ПОЛИТИКИ БЕЗ ПРОВЕРКИ ЗАПИСИ (USING без WITH CHECK) ═══'
\echo ''

SELECT schemaname AS "схема",
       tablename  AS "таблица",
       policyname AS "политика",
       cmd        AS "операция",
       COALESCE(array_to_string(roles, ', '), 'все роли') AS "для кого"
  FROM pg_policies
 WHERE cmd IN ('ALL','UPDATE','INSERT')
   AND with_check IS NULL
 ORDER BY 1, 2;

\echo 'ЧТО ЗНАЧИТ: USING решает, какие строки ВИДНО. WITH CHECK решает, что'
\echo 'можно ЗАПИСАТЬ. Политика на запись без WITH CHECK позволяет изменить'
\echo 'видимую строку на что угодно — например, переписать чужой идентификатор'
\echo 'владельца и присвоить себе чужие данные.'
\echo ''

\echo '═══ 6. ПОЛИТИКИ, ДЕЙСТВУЮЩИЕ НА ВСЕХ, ВКЛЮЧАЯ АНОНИМА ═══'
\echo ''

SELECT schemaname AS "схема", tablename AS "таблица",
       policyname AS "политика", cmd AS "операция"
  FROM pg_policies
 WHERE roles IS NULL OR roles = '{public}'
 ORDER BY 1, 2;

\echo 'ЧТО ЗНАЧИТ: политика без указания роли применяется ко ВСЕМ, включая'
\echo 'анонима. Частая ошибка: скопировали политику чтения, добавили запись,'
\echo 'а роль указать забыли.'
\echo 'ЧИНИТЬ: дописать TO authenticated (или нужную роль).'
\echo ''

\echo '═══ 7. ВЬЮХИ, ВЫПОЛНЯЮЩИЕСЯ ОТ ИМЕНИ АВТОРА ═══'
\echo ''

SELECT n.nspname AS "схема", c.relname AS "вьюха",
       pg_get_userbyid(c.relowner) AS "владелец"
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind = 'v'
   AND n.nspname NOT IN ('pg_catalog','information_schema')
   AND (c.reloptions IS NULL
        OR NOT ('security_invoker=true' = ANY(c.reloptions)))
 ORDER BY 1, 2;

\echo 'ЧТО ЗНАЧИТ: вьюха по умолчанию работает с правами того, кто её создал,'
\echo 'а не того, кто её читает. Поэтому вьюха может отдать строки, которые'
\echo 'политика на самой таблице запретила — обход RLS в обход RLS.'
\echo 'ЧИНИТЬ (PostgreSQL 15+): ALTER VIEW имя SET (security_invoker = true);'
\echo ''

\echo '═══ 8. РАСШИРЕНИЯ, УСТАНОВЛЕННЫЕ В ПУБЛИЧНУЮ СХЕМУ ═══'
\echo ''

SELECT e.extname AS "расширение", n.nspname AS "схема"
  FROM pg_extension e
  JOIN pg_namespace n ON n.oid = e.extnamespace
 WHERE n.nspname = 'public';

\echo 'ЧТО ЗНАЧИТ: расширения в public смешивают служебные функции с вашими'
\echo 'и усложняют контроль прав. Рекомендуется отдельная схема extensions.'
\echo ''

\echo '═══════════════════════════════════════════════════════════'
\echo 'ИТОГ. Смотрите в таком порядке:'
\echo '  Блок 2 — DELETE/UPDATE у anon    -> КРАСНОЕ, чинить сегодня'
\echo '  Блок 3 — DEFINER без search_path -> КРАСНОЕ, чинить сегодня'
\echo '  Блок 4 — лишние функции у anon   -> КРАСНОЕ, чинить сегодня'
\echo '  Блок 1 — таблицы без RLS         -> оранжевое'
\echo '  Блоки 5-7 — политики и вьюхи     -> оранжевое'
\echo '  Блок 8 — расширения              -> жёлтое'
\echo ''
\echo 'Закрывать: guard-data. Перед КАЖДЫМ изменением прав — дамп базы.'
\echo 'После изменений — проверить, что сайт работает: неверно снятые права'
\echo 'ломают приложение мгновенно.'
\echo '═══════════════════════════════════════════════════════════'
