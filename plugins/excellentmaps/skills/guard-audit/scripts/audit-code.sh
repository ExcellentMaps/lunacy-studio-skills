#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# audit-code.sh — аудит кода проекта: секреты, зависимости, опасные места
# Guard Security Suite © ExcellentMaps — github.com/ExcellentMaps
#
# ЧТО ДЕЛАЕТ: читает файлы проекта и ищет типовые проблемы.
# ЧТО НЕ ДЕЛАЕТ: ничего не меняет, ничего не отправляет наружу,
#                не запускает код проекта.
#
# ЗАПУСК:  bash audit-code.sh [путь-к-проекту]   (по умолчанию: текущая папка)
# ТРЕБУЕТ: grep. Опционально: git, npm, gitleaks, osv-scanner — если есть,
#          используются; если нет, скрипт скажет, чего не хватает.
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail

ROOT="${1:-.}"
cd "$ROOT" 2>/dev/null || { echo "Папка $ROOT не найдена"; exit 1; }

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
FAIL=0; WARN=0

hdr()  { printf '\n%s──%s %s %s──%s\n' "$DIM" "$OFF" "$1" "$DIM" "$OFF"; }
ok()   { printf '  %s+%s %s\n' "$GRN" "$OFF" "$1"; }
bad()  { printf '  %s!!%s %s\n     %s-> %s%s\n' "$RED" "$OFF" "$1" "$DIM" "$2" "$OFF"; FAIL=$((FAIL+1)); }
warnn(){ printf '  %s?%s %s\n     %s-> %s%s\n'  "$YEL" "$OFF" "$1" "$DIM" "$2" "$OFF"; WARN=$((WARN+1)); }
note() { printf '     %s%s%s\n' "$DIM" "$1" "$OFF"; }

# Папки, которые читать бессмысленно
EX=(--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor
    --exclude-dir=dist --exclude-dir=build --exclude-dir=.next
    --exclude-dir=__pycache__ --exclude-dir=.venv --exclude-dir=coverage)

# Показать до 8 совпадений по регэкспу
show() {
  local hits
  hits=$(grep -rEIn "${EX[@]}" -e "$1" . 2>/dev/null | head -8)
  [ -n "$hits" ] || return 1
  while IFS= read -r line; do
    [ -n "$line" ] && note "${line:0:150}"
  done <<< "$hits"
  return 0
}

# $1 регэксп, $2 описание, $3 куда идти, $4 уровень (bad|warn)
check() {
  local hits
  hits=$(grep -rEIn "${EX[@]}" -e "$1" . 2>/dev/null | head -8)
  [ -n "$hits" ] || return 0
  if [ "${4:-warn}" = "bad" ]; then bad "$2" "$3"; else warnn "$2" "$3"; fi
  while IFS= read -r line; do
    [ -n "$line" ] && note "${line:0:150}"
  done <<< "$hits"
}

printf '%s═══ Аудит кода: %s ═══%s\n' "$DIM" "$(pwd)" "$OFF"

# ── 1. Секреты в коде ─────────────────────────────────────────────────
hdr "1. Секреты и ключи в коде"
SECRET_RE='(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key|password|jwt[_-]?secret|service[_-]?role|client[_-]?secret)[[:space:]]*[:=][[:space:]]*.{12,}'
if grep -rEIl "${EX[@]}" -e "$SECRET_RE" . >/dev/null 2>&1; then
  bad "Похоже на секреты прямо в коде" "guard-server -> references/секреты-и-ключи.md"
  show "$SECRET_RE" || true
  note "Проверьте вручную: часть находок может быть примерами или заглушками."
else
  ok "Явных секретов в коде не найдено"
fi

# Ключи известных форматов — это почти всегда настоящая утечка
for T in 'sk-[A-Za-z0-9]{20,}' 'ghp_[A-Za-z0-9]{30,}' 'AKIA[0-9A-Z]{16}' \
         'AIza[0-9A-Za-z_-]{30,}' 'BEGIN [A-Z ]*PRIVATE KEY'; do
  if grep -rEIl "${EX[@]}" -e "$T" . >/dev/null 2>&1; then
    bad "Ключ известного формата в коде" "считать скомпрометированным: выпустить новый, отозвать старый"
    show "$T" || true
  fi
done

# ── 2. Секреты в git ──────────────────────────────────────────────────
hdr "2. Секреты в истории git"
if [ -d .git ]; then
  TRACKED=$(git ls-files 2>/dev/null | grep -E '(^|/)\.env|secrets?\.(env|json|ya?ml)$|\.pem$|\.key$|id_rsa' | head -10)
  if [ -n "$TRACKED" ]; then
    bad "Файлы с секретами лежат в git" "удалить из истории И ротировать все ключи из них"
    while IFS= read -r f; do [ -n "$f" ] && note "$f"; done <<< "$TRACKED"
  else
    ok "Файлов с секретами в git не видно"
  fi
  if [ -f .gitignore ]; then
    if grep -qE '(^|/)\.env' .gitignore; then
      ok ".env указан в .gitignore"
    else
      warnn ".env не указан в .gitignore" "однажды закоммитится случайно"
    fi
  else
    warnn "Нет файла .gitignore" "создать и внести .env, ключи, дампы базы"
  fi
  if command -v gitleaks >/dev/null 2>&1; then
    note "Запускаю gitleaks по истории..."
    gitleaks detect --no-banner --redact 2>&1 | tail -20 || true
  else
    note "gitleaks не установлен — глубокая проверка истории пропущена."
    note "Поставить: https://github.com/gitleaks/gitleaks"
  fi
else
  note "Это не git-репозиторий — проверка истории пропущена."
fi

# ── 3. Опасные конструкции ────────────────────────────────────────────
hdr "3. Опасные конструкции в коде"
BEFORE=$((FAIL + WARN))

check 'dangerouslySetInnerHTML|v-html|\.innerHTML[[:space:]]*=' \
      "Данные вставляются в страницу как разметка — возможен XSS" \
      "guard-frontend -> references/xss-и-вывод.md"

check 'eval\(|new Function\(' \
      "Выполнение строки как кода (eval)" \
      "guard-frontend -> references/xss-и-вывод.md" bad

check '(SELECT|INSERT|UPDATE|DELETE)[^;]*\+[[:space:]]*(req|request|params|query|body|input|user)' \
      "SQL собирается склейкой строк — возможна SQL-инъекция" \
      "guard-data -> references/sql-инъекции.md" bad

check 'localStorage\.setItem\([^)]*(token|jwt|session|password|secret)' \
      "Токен или секрет кладётся в localStorage" \
      "guard-frontend -> references/хранилище-и-куки.md"

check 'verify[_ ]?ssl[[:space:]]*=[[:space:]]*False|rejectUnauthorized[[:space:]]*:[[:space:]]*false|InsecureSkipVerify[[:space:]]*:[[:space:]]*true' \
      "Проверка сертификата отключена" \
      "guard-server -> references/https-и-сертификаты.md" bad

check 'md5\(|sha1\(' \
      "Устаревший алгоритм хеширования" \
      "guard-auth -> references/пароли-и-сессии.md"

check 'SECURITY DEFINER' \
      "Есть SECURITY DEFINER-функции: у КАЖДОЙ должен быть закреплён search_path" \
      "guard-data -> references/rls-и-права.md"

check 'Access-Control-Allow-Origin[^;]*\*' \
      "CORS открыт для всех доменов" \
      "guard-server -> references/заголовки-и-csp.md"

[ $((FAIL + WARN)) -eq "$BEFORE" ] && ok "Типовых опасных конструкций не найдено"

# ── 4. Конфигурация ───────────────────────────────────────────────────
hdr "4. Конфигурация"
FOUND_ENV=0
for F in .env .env.local .env.production secrets.env; do
  if [ -f "$F" ]; then
    FOUND_ENV=1
    P=$(stat -c '%a' "$F" 2>/dev/null || echo '?')
    if [ "$P" = "600" ] || [ "$P" = "400" ]; then
      ok "$F — права $P (читает только владелец)"
    else
      warnn "$F — права $P" "поставить только владельцу: chmod 600 $F"
    fi
  fi
done
[ "$FOUND_ENV" -eq 0 ] && note "Файлов .env в корне не найдено."

if grep -rqEI "${EX[@]}" -e '\b(DEBUG|debug)[[:space:]]*[:=][[:space:]]*(true|True|1)\b' . 2>/dev/null; then
  warnn "Где-то включён режим отладки" "в бою он показывает внутренности при ошибке"
fi

# ── 5. Зависимости ────────────────────────────────────────────────────
hdr "5. Зависимости"
if [ -f package.json ]; then
  if [ -f package-lock.json ] || [ -f yarn.lock ] || [ -f pnpm-lock.yaml ]; then
    ok "Файл блокировки версий на месте"
  else
    bad "Нет lock-файла" "на сервере соберутся другие версии, чем вы проверяли"
  fi
  if command -v npm >/dev/null 2>&1; then
    note "Запускаю npm audit (только боевые зависимости)..."
    npm audit --omit=dev 2>/dev/null | tail -15 || note "npm audit не отработал"
  fi
fi
[ -f requirements.txt ] && note "Python-проект: проверьте pip-audit"
[ -f go.mod ] && note "Go-проект: проверьте govulncheck"
[ -f composer.json ] && note "PHP-проект: проверьте composer audit"

if command -v osv-scanner >/dev/null 2>&1; then
  note "Запускаю osv-scanner..."
  osv-scanner scan source -r . 2>&1 | tail -20 || true
else
  note "osv-scanner не установлен (рекомендуется): https://github.com/google/osv-scanner"
fi

# ── 6. Итог ───────────────────────────────────────────────────────────
printf '\n%s═══ Итог по коду ═══%s\n' "$DIM" "$OFF"
printf '  %sНадо закрыть: %d%s   %sНадо посмотреть: %d%s\n\n' \
  "$RED" "$FAIL" "$OFF" "$YEL" "$WARN" "$OFF"
echo "  ${DIM}Скрипт ловит типовое и не заменяет чтение кода:${OFF}"
echo "  ${DIM}логика прав и доступ к чужим записям проверяются глазами.${OFF}"
echo "  ${DIM}Снаружи — audit-live.sh. База — audit-db.sql.${OFF}"
exit 0
