#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# audit-live.sh — проверка живого сайта снаружи
# Guard Security Suite © ExcellentMaps — github.com/ExcellentMaps
#
# ЧТО ДЕЛАЕТ: смотрит, что сайт отдаёт наружу. Заголовки, TLS, файлы
# политики, доступность служебных путей, реакция на ботов.
#
# ЧТО НЕ ДЕЛАЕТ: ничего не меняет, не подбирает пароли, не нагружает.
# Все запросы — обычные GET/HEAD, как у браузера.
#
# ЗАПУСК:  bash audit-live.sh ваш-домен.ru
# ТРЕБУЕТ: curl. Желательно openssl (для проверки сертификата).
#
# ⚠️ Только для СВОЕГО сайта. Проверка чужого домена без разрешения
#    владельца — недопустима.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  echo "Использование: bash audit-live.sh ваш-домен.ru"
  exit 1
fi
DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"
BASE="https://$DOMAIN"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
FAIL=0; WARN=0; PASS=0

hdr()  { printf '\n%s──%s %s %s──%s\n' "$DIM" "$OFF" "$1" "$DIM" "$OFF"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$OFF" "$1"; PASS=$((PASS+1)); }
bad()  { printf '  %s✗%s %s\n     %s→ %s%s\n' "$RED" "$OFF" "$1" "$DIM" "$2" "$OFF"; FAIL=$((FAIL+1)); }
warnn(){ printf '  %s!%s %s\n     %s→ %s%s\n' "$YEL" "$OFF" "$1" "$DIM" "$2" "$OFF"; WARN=$((WARN+1)); }

HEADERS="$(curl -sS -I -m 15 -A 'Mozilla/5.0 (guard-audit)' "$BASE/" 2>/dev/null)"
if [ -z "$HEADERS" ]; then
  echo "${RED}Сайт $BASE не отвечает. Проверьте домен и доступность.${OFF}"
  exit 1
fi
has() { grep -qi "^$1:" <<<"$HEADERS"; }
val() { grep -i "^$1:" <<<"$HEADERS" | head -1 | cut -d: -f2- | sed 's/^ *//;s/\r//'; }
code_of() { curl -sS -o /dev/null -w '%{http_code}' -m 15 -A "${2:-Mozilla/5.0 (guard-audit)}" "$1" 2>/dev/null; }

printf '%s═══ Аудит %s ═══%s\n' "$DIM" "$BASE" "$OFF"

# ── 1. HTTPS ──────────────────────────────────────────────────────────
hdr "1. Защищённое соединение"
HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' -m 15 "http://$DOMAIN/" 2>/dev/null)"
if [[ "$HTTP_CODE" =~ ^30 ]]; then
  ok "Обычный http перенаправляется на https"
else
  bad "http не перенаправляется на https (код $HTTP_CODE)" \
      "guard-server → references/https-и-сертификаты.md"
fi
if command -v openssl >/dev/null 2>&1; then
  EXP="$(echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
  if [ -n "$EXP" ]; then
    EXP_S="$(date -d "$EXP" +%s 2>/dev/null || echo 0)"
    NOW_S="$(date +%s)"
    if [ "$EXP_S" -gt 0 ]; then
      DAYS=$(( (EXP_S - NOW_S) / 86400 ))
      if   [ "$DAYS" -lt 0 ];  then bad "Сертификат истёк" "срочно продлить"
      elif [ "$DAYS" -lt 14 ]; then warnn "Сертификат истекает через $DAYS дн." "проверьте автопродление"
      else ok "Сертификат действителен ещё $DAYS дн."; fi
    fi
  fi
fi

# ── 2. Заголовки безопасности ─────────────────────────────────────────
hdr "2. Заголовки безопасности"
has "strict-transport-security" \
  && ok "HSTS — браузер запомнит: только защищённое соединение" \
  || bad "Нет Strict-Transport-Security" "guard-server → references/заголовки-и-csp.md"

if has "content-security-policy"; then
  CSP="$(val content-security-policy)"
  ok "CSP присутствует"
  grep -q "unsafe-inline" <<<"$CSP" && grep -q "script-src" <<<"$CSP" \
    && warnn "В CSP есть unsafe-inline для скриптов" "ослабляет защиту от вставки чужого кода"
  grep -q "frame-ancestors" <<<"$CSP" \
    || warnn "В CSP нет frame-ancestors" "сайт можно встроить в чужую страницу"
else
  bad "Нет Content-Security-Policy" "главный заголовок против вставки чужого кода"
fi

has "x-content-type-options" && ok "nosniff — браузер не угадывает тип файла" \
  || bad "Нет X-Content-Type-Options: nosniff" "загруженная «картинка» с кодом может выполниться"
has "referrer-policy" && ok "Referrer-Policy задан" \
  || warnn "Нет Referrer-Policy" "чужие сайты видят, с какой страницы пришли"
has "permissions-policy" && ok "Permissions-Policy задан" \
  || warnn "Нет Permissions-Policy" "страница может запрашивать камеру и геолокацию"
{ has "x-frame-options" || grep -qi "frame-ancestors" <<<"$(val content-security-policy)"; } \
  && ok "Встраивание в чужую страницу запрещено" \
  || bad "Сайт можно встроить в чужой сайт" "защита от подмены интерфейса"

# ── 3. Утечка информации о сервере ────────────────────────────────────
hdr "3. Что сервер рассказывает о себе"
SRV="$(val server)"
if grep -qE '[0-9]+\.[0-9]+' <<<"$SRV"; then
  warnn "Сервер называет свою версию: $SRV" "server_tokens off; — меньше подсказок сканеру"
else
  ok "Версия сервера не раскрывается${SRV:+ ($SRV)}"
fi
has "x-powered-by" && warnn "Заголовок X-Powered-By: $(val x-powered-by)" "убрать — лишняя подсказка" \
  || ok "X-Powered-By не отдаётся"

# ── 4. Служебные файлы наружу ─────────────────────────────────────────
hdr "4. Служебные файлы (не должны открываться)"
for P in .env .git/config .git/HEAD docker-compose.yml package.json \
         config.php wp-config.php .DS_Store backup.sql dump.sql \
         phpinfo.php server-status .htaccess secrets.env; do
  C="$(code_of "$BASE/$P")"
  if [ "$C" = "200" ]; then
    bad "ОТКРЫТ файл /$P" "закрыть немедленно — guard-server"
  fi
done
[ "$FAIL" -eq 0 ] && echo "  ${DIM}(проверено 15 типовых путей)${OFF}"
ok "Проверка служебных файлов завершена"

# ── 5. Файлы ИИ-политики ──────────────────────────────────────────────
hdr "5. Политика доступа для ИИ и ботов"
for F in robots.txt llms.txt .well-known/ai.txt .well-known/security.txt .well-known/tdmrep.json; do
  C="$(code_of "$BASE/$F")"
  if [ "$C" = "200" ]; then ok "/$F отдаётся"
  else warnn "/$F отсутствует (код $C)" "guard-ai-policy → templates/"; fi
done
XR="$(val x-robots-tag)"
[ -n "$XR" ] && ok "X-Robots-Tag: $XR" \
  || warnn "Нет заголовка X-Robots-Tag" "мета-теги не закрывают картинки и PDF"

# ── 6. Реакция на ботов ───────────────────────────────────────────────
hdr "6. Блокировка ботов и сканеров"
for UA in "GPTBot/1.0" "ClaudeBot/1.0" "sqlmap/1.7" "python-requests/2.31"; do
  C="$(code_of "$BASE/" "$UA")"
  if [ "$C" = "403" ] || [ "$C" = "429" ]; then ok "$UA → отклонён ($C)"
  else warnn "$UA → пропущен ($C)" "guard-ai-policy → templates/nginx-ai-block.conf"; fi
done
CB="$(code_of "$BASE/" "Mozilla/5.0 (guard-audit)")"
[ "$CB" = "200" ] && ok "Обычный браузер проходит ($CB) — живые люди не пострадали" \
  || bad "Обычный браузер получает $CB" "блокировка задела реальных пользователей!"

# ── 7. Итог ───────────────────────────────────────────────────────────
printf '\n%s═══ Итог ═══%s\n' "$DIM" "$OFF"
printf '  %sВ порядке: %d%s   %sНадо посмотреть: %d%s   %sНадо закрыть: %d%s\n\n' \
  "$GRN" "$PASS" "$OFF" "$YEL" "$WARN" "$OFF" "$RED" "$FAIL" "$OFF"
if [ "$FAIL" -gt 0 ]; then
  echo "  Сначала закройте красное. Каждый пункт указывает, какой скилл его закрывает."
elif [ "$WARN" -gt 0 ]; then
  echo "  Красного нет. Жёлтое — в плановом порядке."
else
  echo "  Снаружи всё закрыто. Остальные блоки аудита — по коду и базе."
fi
echo
echo "  ${DIM}Это только внешняя проверка (блоки 2, 3, 10 из 12).${OFF}"
echo "  ${DIM}Полный аудит: audit-code.sh (код и секреты) и audit-db.sql (база).${OFF}"
exit 0
