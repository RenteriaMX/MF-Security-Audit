#!/usr/bin/env bash
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[1;31m'; YEL='\033[1;33m'; GRN='\033[1;32m'
CYN='\033[1;36m'; MAG='\033[1;35m'; DIM='\033[2;37m'; RST='\033[0m'
BOLD='\033[1m'

_hdr()  { printf "\n${BOLD}${CYN}━━ %s${RST}\n" "$*"; }
_ok()   { printf "  ${GRN}✓${RST} %s\n" "$*"; }
_warn() { printf "  ${YEL}⚠${RST}  %s\n" "$*"; }
_fail() { printf "  ${RED}✗${RST} %s\n" "$*"; }
_info() { printf "  ${DIM}→${RST} %s\n" "$*"; }

# ─── Progress animation ───────────────────────────────────────────────────────
_build_anim() {
  local pid="$1"
  local colors=("\033[1;36m" "\033[1;35m" "\033[1;33m" "\033[1;32m")
  local dim="\033[2;37m" rst="\033[0m"
  local idx=0 secs=0
  while kill -0 "$pid" 2>/dev/null; do
    local line="  "
    for j in 0 1 2 3; do
      if [ $j -eq $((idx % 4)) ]; then
        line+="${colors[$j]}●${rst} "
      else
        line+="${dim}○${rst} "
      fi
    done
    printf "\r${line} ${dim}analizando${rst}  %02d:%02d" $((secs/60)) $((secs%60)) > /dev/tty
    sleep 1
    ((idx++)) || true; ((secs++)) || true
  done
  printf "\r%60s\r" > /dev/tty
}

_run_anim() {
  local log="$1"; shift
  "$@" > "$log" 2>&1 &
  local _PID=$!
  _build_anim "$_PID" &
  local _ANIM_PID=$!
  wait $_PID && _EXIT=0 || _EXIT=$?
  kill $_ANIM_PID 2>/dev/null || true; wait $_ANIM_PID 2>/dev/null || true
  return $_EXIT
}

# ─── Globals ──────────────────────────────────────────────────────────────────
WARNS=0
CRITS=0
FRONTEND_DIR=""

_bump_warn() { ((WARNS++)) || true; }
_bump_crit() { ((CRITS++)) || true; }

# ─── Detect frontend directory ────────────────────────────────────────────────
_detect_frontend() {
  if [[ -n "${1:-}" ]]; then
    FRONTEND_DIR="$1"
  elif [[ -n "${PLONE_BASE:-}" ]]; then
    # PLONE_BASE apunta a la raíz del proyecto; frontend suele estar en frontend/
    if [[ -d "${PLONE_BASE}/frontend" ]]; then
      FRONTEND_DIR="${PLONE_BASE}/frontend"
    else
      FRONTEND_DIR="${PLONE_BASE}"
    fi
  else
    local DEFAULT="/opt/plone/web-plone"
    if [[ -d "${DEFAULT}/frontend" ]]; then
      FRONTEND_DIR="${DEFAULT}/frontend"
    elif [[ -d "$DEFAULT" ]]; then
      FRONTEND_DIR="$DEFAULT"
    else
      _fail "No se encontró directorio frontend. Usa: $0 /ruta/a/frontend"
      exit 1
    fi
  fi

  if [[ ! -f "${FRONTEND_DIR}/package.json" ]]; then
    _fail "No existe package.json en ${FRONTEND_DIR}"
    exit 1
  fi
  _ok "Frontend: ${FRONTEND_DIR}"
}

# ─── Check: pnpm-lock.yaml integridad ────────────────────────────────────────
_check_lockfile() {
  _hdr "1/4  Integridad del lockfile"

  if [[ ! -f "${FRONTEND_DIR}/pnpm-lock.yaml" ]]; then
    _warn "No existe pnpm-lock.yaml — no se puede verificar integridad"
    _bump_warn
    return
  fi

  local log="/tmp/audit_lock_$$.log"
  _info "Verificando hashes (frozen-lockfile dry-run)…"

  if _run_anim "$log" pnpm --dir "${FRONTEND_DIR}" install --frozen-lockfile --dry-run; then
    _ok "Lockfile íntegro — sin modificaciones detectadas"
  else
    _fail "El lockfile no coincide con package.json o fue modificado"
    _bump_crit
    _info "Detalle: $log"
  fi
  rm -f "$log"
}

# ─── Check: vulnerabilidades HIGH/CRITICAL ────────────────────────────────────
_check_audit() {
  _hdr "2/4  Vulnerabilidades npm (pnpm audit)"

  local log="/tmp/audit_vuln_$$.log"
  _info "Escaneando dependencias contra base de datos de CVEs…"

  local exit_code=0
  _run_anim "$log" pnpm --dir "${FRONTEND_DIR}" audit --audit-level=high --json || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    _ok "Sin vulnerabilidades HIGH o CRITICAL"
  else
    # Parsear JSON si jq está disponible
    if command -v jq &>/dev/null && [[ -s "$log" ]]; then
      local total high critical
      total=$(jq -r '.metadata.vulnerabilities | (.high // 0) + (.critical // 0)' "$log" 2>/dev/null || echo "?")
      high=$(jq -r '.metadata.vulnerabilities.high // 0' "$log" 2>/dev/null || echo "?")
      critical=$(jq -r '.metadata.vulnerabilities.critical // 0' "$log" 2>/dev/null || echo "?")

      if [[ "${critical}" != "0" && "${critical}" != "?" ]]; then
        _fail "CRITICAL: ${critical}  HIGH: ${high}"
        _bump_crit
        # Mostrar paquetes afectados
        jq -r '.advisories // {} | to_entries[] | select(.value.severity == "critical" or .value.severity == "high") |
          "    \(.value.severity | ascii_upcase)  \(.value.module_name)  — \(.value.title)"' "$log" 2>/dev/null || true
      elif [[ "${high}" != "0" && "${high}" != "?" ]]; then
        _warn "HIGH: ${high}  (sin CRITICAL)"
        _bump_warn
        jq -r '.advisories // {} | to_entries[] | select(.value.severity == "high") |
          "    HIGH  \(.value.module_name)  — \(.value.title)"' "$log" 2>/dev/null || true
      fi
    else
      _fail "Vulnerabilidades encontradas (instala jq para detalle). Código: ${exit_code}"
      _bump_crit
      _info "Log: $log"; return
    fi
  fi
  rm -f "$log"
}

# ─── Check: scripts postinstall sospechosos ──────────────────────────────────
_check_postinstall() {
  _hdr "3/4  Scripts postinstall en node_modules"

  local nm="${FRONTEND_DIR}/node_modules"
  if [[ ! -d "$nm" ]]; then
    _warn "node_modules no existe — ejecuta pnpm install primero"
    _bump_warn
    return
  fi

  _info "Buscando scripts postinstall…"
  local log="/tmp/audit_post_$$.log"

  # Buscar package.json con scripts.postinstall
  find "$nm" -maxdepth 3 -name "package.json" \
    ! -path "*/node_modules/*/node_modules/*" \
    -exec grep -l '"postinstall"' {} \; 2>/dev/null > "$log" || true

  local count
  count=$(wc -l < "$log" | tr -d ' ')

  if [[ "$count" -eq 0 ]]; then
    _ok "Sin scripts postinstall detectados"
    rm -f "$log"
    return
  fi

  # Clasificar: sospechosos vs comunes conocidos
  local WHITELIST="esbuild|@swc|sharp|canvas|node-gyp|grpc|fsevents|keytar|robotjs|bcrypt|sqlite3|better-sqlite3|nodegit|libsass|node-sass|cypress|electron"
  local suspicious=()
  local benign=0

  while IFS= read -r pkgjson; do
    local pkg_name
    pkg_name=$(grep -m1 '"name"' "$pkgjson" | sed 's/.*"name": *"\([^"]*\)".*/\1/' 2>/dev/null || echo "desconocido")
    local script
    script=$(grep -A2 '"postinstall"' "$pkgjson" | head -3 | tr '\n' ' ')

    if echo "$pkg_name" | grep -qE "$WHITELIST"; then
      ((benign++)) || true
    else
      suspicious+=("${pkg_name}  →  ${script}")
    fi
  done < "$log"
  rm -f "$log"

  if [[ ${#suspicious[@]} -eq 0 ]]; then
    _ok "Postinstall encontrados: ${count} (todos en whitelist de paquetes conocidos)"
  else
    _warn "${#suspicious[@]} paquete(s) con postinstall fuera de whitelist:"
    for entry in "${suspicious[@]}"; do
      printf "    ${YEL}!${RST}  %s\n" "$entry"
    done
    _bump_warn
  fi
  [[ $benign -gt 0 ]] && _info "Paquetes nativos en whitelist: ${benign} (normal)"
}

# ─── Check: typosquatting básico ─────────────────────────────────────────────
_check_typosquatting() {
  _hdr "4/4  Typosquatting básico"

  local pkgjson="${FRONTEND_DIR}/package.json"

  # Extraer todos los nombres de dependencias
  local deps
  if command -v jq &>/dev/null; then
    deps=$(jq -r '(.dependencies // {}) + (.devDependencies // {}) | keys[]' "$pkgjson" 2>/dev/null)
  else
    deps=$(grep -E '^\s+"[^"]+":' "$pkgjson" | grep -v '"name"\|"version"\|"description"\|"license"' | sed 's/.*"\([^"]*\)".*/\1/')
  fi

  local found_typos=()

  while IFS= read -r pkg; do
    [[ -z "$pkg" ]] && continue

    # 1. Paquetes que parecen @plone/* pero no son
    if echo "$pkg" | grep -qiE '^@pl[o0][n][e]' && ! echo "$pkg" | grep -qE '^@plone/'; then
      found_typos+=("${pkg}  → sospecha de typosquat de @plone/*")
    fi

    # 2. Variantes de "volto" con sustituciones
    if echo "$pkg" | grep -qiE '(v[o0]lt[o0]|v0lt[o0]|volt0)' && ! echo "$pkg" | grep -qE '^(@plone/volto|volto-)'; then
      found_typos+=("${pkg}  → sospecha de typosquat de volto")
    fi

    # 3. @plonegovbr imitadores
    if echo "$pkg" | grep -qiE '@pl[o0]neg[o0]vbr' && ! echo "$pkg" | grep -qE '^@plonegovbr/'; then
      found_typos+=("${pkg}  → sospecha de typosquat de @plonegovbr/*")
    fi

    # 4. Prefijos cuasi-plone sin @ (plone- sin ser volto addon oficial)
    if echo "$pkg" | grep -qiE '^pl[o0]ne-' && ! echo "$pkg" | grep -qE '^plone-(compile|moment|protect-string)'; then
      found_typos+=("${pkg}  → paquete plone-* sin prefijo @plone/")
    fi

    # 5. Paquetes que intentan suplantar volto-* oficiales con caracteres similares
    if echo "$pkg" | grep -qiE '^v[o0]lt[o0]-' && ! echo "$pkg" | grep -qE '^volto-'; then
      found_typos+=("${pkg}  → variante sospechosa de volto-*")
    fi

  done <<< "$deps"

  if [[ ${#found_typos[@]} -eq 0 ]]; then
    _ok "Sin paquetes sospechosos de typosquatting"
  else
    _fail "${#found_typos[@]} paquete(s) potencialmente maliciosos:"
    for t in "${found_typos[@]}"; do
      printf "    ${RED}✗${RST}  %s\n" "$t"
    done
    _bump_crit
  fi

  # Estadística: cuántos paquetes Volto/Plone hay en total
  local volto_count
  volto_count=$(echo "$deps" | grep -cE '^(@plone/|@plonegovbr/|volto-)' || true)
  [[ $volto_count -gt 0 ]] && _info "Paquetes @plone/ / @plonegovbr/ / volto-* verificados: ${volto_count}"
}

# ─── Summary ──────────────────────────────────────────────────────────────────
_summary() {
  printf "\n${BOLD}${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n"
  printf "${BOLD}   Resumen de auditoría${RST}\n"
  printf "${BOLD}${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n\n"

  if [[ $CRITS -eq 0 && $WARNS -eq 0 ]]; then
    printf "  ${GRN}✓  Sin problemas detectados${RST}\n\n"
    exit 0
  elif [[ $CRITS -eq 0 ]]; then
    printf "  ${YEL}⚠  ${WARNS} advertencia(s) — revisar antes de deploy${RST}\n\n"
    exit 1
  else
    printf "  ${RED}✗  ${CRITS} crítico(s)  ${YEL}⚠ ${WARNS} advertencia(s)${RST}\n"
    printf "  ${RED}   Acción requerida antes de producción${RST}\n\n"
    exit 2
  fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  printf "\n${BOLD}${CYN}  Plone Security Audit${RST}  ${DIM}supply chain + vulnerabilidades${RST}\n"
  printf "${DIM}  ──────────────────────────────────────────${RST}\n"

  if ! command -v pnpm &>/dev/null; then
    _fail "pnpm no encontrado. Instala con: npm install -g pnpm"
    exit 1
  fi

  _detect_frontend "${1:-}"
  _check_lockfile
  _check_audit
  _check_postinstall
  _check_typosquatting
  _summary
}

main "$@"
