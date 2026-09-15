#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# verify-integrity.sh — проверка, что копия набора не изменена
# Guard Security Suite © ExcellentMaps — github.com/ExcellentMaps
#
# ЗАЧЕМ: подтвердить, что полученная копия — оригинальный набор,
# а не переименованная или изменённая версия.
#
# ЗАПУСК:
#   bash verify-integrity.sh          — проверить копию по SHA256SUMS
#   bash verify-integrity.sh --create — пересобрать SHA256SUMS (только автор)
#
# ТРЕБУЕТ: sha256sum (Linux, WSL, Git Bash) или shasum (macOS).
# ═══════════════════════════════════════════════════════════════════════
set -uo pipefail
cd "$(dirname "$0")" || exit 1

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
SUMS="SHA256SUMS"

if command -v sha256sum >/dev/null 2>&1; then
  HASH() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  HASH() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "${RED}Не найден sha256sum или shasum — проверка невозможна.${OFF}"
  exit 1
fi

# Файлы набора, кроме самого списка контрольных сумм
list_files() {
  find . -type f \
    ! -name "$SUMS" \
    ! -path "./.git/*" \
    ! -name '.DS_Store' \
    | sed 's|^\./||' | LC_ALL=C sort
}

# ── Режим пересборки списка (для автора) ──────────────────────────────
if [ "${1:-}" = "--create" ]; then
  : > "$SUMS"
  {
    echo "# Guard Security Suite — контрольные суммы файлов"
    echo "# (c) ExcellentMaps — github.com/ExcellentMaps"
    echo "# Проверка: bash verify-integrity.sh"
    echo "#"
  } >> "$SUMS"
  COUNT=0
  while IFS= read -r f; do
    printf '%s  %s\n' "$(HASH "$f")" "$f" >> "$SUMS"
    COUNT=$((COUNT + 1))
  done < <(list_files)
  echo "${GRN}Записано $COUNT файлов в $SUMS${OFF}"
  exit 0
fi

# ── Режим проверки ────────────────────────────────────────────────────
if [ ! -f "$SUMS" ]; then
  echo "${RED}Файл $SUMS не найден.${OFF}"
  echo "Без него подтвердить подлинность копии нельзя."
  echo "Скачайте оригинал: https://github.com/ExcellentMaps"
  exit 1
fi

echo "${DIM}═══ Проверка целостности Guard Security Suite ═══${OFF}"
echo

CHANGED=0; MISSING=0; OK_N=0

while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  EXPECTED="${line%% *}"
  FILE="${line#*  }"
  if [ ! -f "$FILE" ]; then
    printf '  %sОТСУТСТВУЕТ%s  %s\n' "$RED" "$OFF" "$FILE"
    MISSING=$((MISSING + 1))
    continue
  fi
  ACTUAL="$(HASH "$FILE")"
  if [ "$ACTUAL" = "$EXPECTED" ]; then
    OK_N=$((OK_N + 1))
  else
    printf '  %sИЗМЕНЁН%s      %s\n' "$RED" "$OFF" "$FILE"
    CHANGED=$((CHANGED + 1))
  fi
done < "$SUMS"

# Лишние файлы, которых нет в списке
EXTRA=0
while IFS= read -r f; do
  if ! grep -qF "  $f" "$SUMS"; then
    printf '  %sЛИШНИЙ%s       %s\n' "$YEL" "$OFF" "$f"
    EXTRA=$((EXTRA + 1))
  fi
done < <(list_files)

echo
if [ "$CHANGED" -eq 0 ] && [ "$MISSING" -eq 0 ] && [ "$EXTRA" -eq 0 ]; then
  printf '  %sКопия оригинальная.%s Проверено файлов: %d\n' "$GRN" "$OFF" "$OK_N"
  echo
  echo "  ${DIM}Автор: ExcellentMaps — github.com/ExcellentMaps${OFF}"
  echo "  ${DIM}Лицензия: CC BY-ND 4.0 (см. LICENSE)${OFF}"
  exit 0
fi

printf '  %sКопия отличается от оригинала.%s\n' "$RED" "$OFF"
printf '  Совпало: %d   Изменено: %d   Отсутствует: %d   Лишних: %d\n' \
  "$OK_N" "$CHANGED" "$MISSING" "$EXTRA"
echo
echo "  ${DIM}Изменённая копия не является оригинальным набором.${OFF}"
echo "  ${DIM}Распространение изменённых версий лицензией не разрешено.${OFF}"
echo "  ${DIM}Оригинал: https://github.com/ExcellentMaps${OFF}"
exit 1
