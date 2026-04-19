#!/usr/bin/env bash
# =============================================================================
# preflight-check.sh
#
# Validates all EvoMaster prerequisites before running run-whitebox.sh.
# Fails fast with clear, colour-coded error messages if anything is missing.
#
# Usage:
#   bash scripts/preflight-check.sh
#
# Exit codes:
#   0  — all checks passed (no FAIL items)
#   1  — one or more checks FAILED
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Colours and helpers
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

OK_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

ok()   { echo -e "  ${GREEN}[OK]${RESET}   $*"; OK_COUNT=$(( OK_COUNT + 1 )); }
warn() { echo -e "  ${YELLOW}[WARN]${RESET} $*"; WARN_COUNT=$(( WARN_COUNT + 1 )); }
fail() { echo -e "  ${RED}[FAIL]${RESET} $*"; FAIL_COUNT=$(( FAIL_COUNT + 1 )); }
hint() { echo -e "         $*"; }

banner() {
  echo
  echo -e "${BOLD}--- $* ---${RESET}"
}

# Cross-platform file modification time (seconds since epoch)
get_mtime() { stat -f "%m" "$1" 2>/dev/null || stat -c "%Y" "$1" 2>/dev/null || echo 0; }

# ---------------------------------------------------------------------------
# CHECK 1: EvoMaster installation
# ---------------------------------------------------------------------------
banner "CHECK 1: EvoMaster installation"

EVOMASTER_DIR=""
for candidate in "${HOME}/evomaster" "/opt/evomaster" "${HOME}/.local/evomaster"; do
  if [[ -f "${candidate}/evomaster.jar" ]]; then
    EVOMASTER_DIR="${candidate}"
    break
  fi
done

EVOMASTER_JAR=""
if [[ -z "${EVOMASTER_DIR}" ]]; then
  fail "evomaster.jar not found in ~/evomaster, /opt/evomaster, or ~/.local/evomaster"
else
  EVOMASTER_JAR="${EVOMASTER_DIR}/evomaster.jar"
  ok "evomaster.jar found: ${EVOMASTER_JAR}"
  if [[ -f "${EVOMASTER_DIR}/evomaster-agent.jar" ]]; then
    ok "evomaster-agent.jar found: ${EVOMASTER_DIR}/evomaster-agent.jar"
  else
    fail "evomaster-agent.jar not found in ${EVOMASTER_DIR}"
  fi
fi

# ---------------------------------------------------------------------------
# CHECK 2: crAPI installation
# ---------------------------------------------------------------------------
banner "CHECK 2: crAPI installation"

CRAPI_DIR=""
for candidate in "/opt/crapi" "${HOME}/.local/crapi"; do
  if [[ -f "${candidate}/identity-service.jar" ]]; then
    CRAPI_DIR="${candidate}"
    break
  fi
done

if [[ -z "${CRAPI_DIR}" ]]; then
  fail "identity-service.jar not found in /opt/crapi or ~/.local/crapi"
else
  ok "identity-service.jar found: ${CRAPI_DIR}/identity-service.jar"
  if [[ -f "${CRAPI_DIR}/jwks.json" ]]; then
    ok "jwks.json found: ${CRAPI_DIR}/jwks.json"
  else
    fail "jwks.json not found in ${CRAPI_DIR}"
  fi
fi

# ---------------------------------------------------------------------------
# CHECK 3: Driver JAR
# ---------------------------------------------------------------------------
banner "CHECK 3: Driver JAR"

DRIVER_JAR="${REPO_ROOT}/evomaster-driver/target/crapi-community-driver-1.0.0.jar"
if [[ -f "${DRIVER_JAR}" ]]; then
  ok "Driver JAR found: ${DRIVER_JAR}"
else
  fail "Driver JAR not found: ${DRIVER_JAR}"
  hint "Build it with: cd evomaster-driver && mvn package -DskipTests"
fi

# ---------------------------------------------------------------------------
# CHECK 4: Docker daemon
# ---------------------------------------------------------------------------
banner "CHECK 4: Docker daemon"

if docker info >/dev/null 2>&1; then
  ok "Docker daemon is running"
else
  fail "Docker daemon is not reachable (docker info failed)"
fi

# ---------------------------------------------------------------------------
# CHECK 5: Required Docker services
# ---------------------------------------------------------------------------
banner "CHECK 5: Required Docker services (postgres, mongodb, mailhog)"

COMPOSE_FILE="${REPO_ROOT}/docker-compose.evomaster.yml"
if [[ ! -f "${COMPOSE_FILE}" ]]; then
  warn "docker-compose.evomaster.yml not found at ${COMPOSE_FILE} — cannot check services"
else
  for svc in postgres mongodb mailhog; do
    svc_state=$(docker compose -f "${COMPOSE_FILE}" ps --format "{{.State}}" "${svc}" 2>/dev/null \
      | head -1 || echo "unknown")
    svc_state="${svc_state:-not_found}"
    if [[ "${svc_state}" == "running" ]]; then
      ok "Service '${svc}' is running"
    else
      warn "Service '${svc}' state: ${svc_state} (run-whitebox.sh will start it)"
    fi
  done
fi

# ---------------------------------------------------------------------------
# CHECK 6: PostgreSQL reachability
# ---------------------------------------------------------------------------
banner "CHECK 6: PostgreSQL reachability"

PG_READY=false
if command -v pg_isready &>/dev/null; then
  if pg_isready -h localhost -p 5432 -U admin -d crapi 2>/dev/null; then
    PG_READY=true
    ok "PostgreSQL is reachable via pg_isready"
  fi
fi

if [[ "${PG_READY}" == "false" ]] && [[ -f "${COMPOSE_FILE}" ]]; then
  PG_CONTAINER=$(docker compose -f "${COMPOSE_FILE}" ps -q postgres 2>/dev/null || true)
  if [[ -n "${PG_CONTAINER}" ]] && docker exec "${PG_CONTAINER}" pg_isready 2>/dev/null; then
    PG_READY=true
    ok "PostgreSQL is reachable via docker exec"
  fi
fi

if [[ "${PG_READY}" == "false" ]]; then
  warn "PostgreSQL not reachable on localhost:5432 (postgres may start when run-whitebox.sh runs)"
fi

# ---------------------------------------------------------------------------
# CHECK 7: Port 8080 availability
# ---------------------------------------------------------------------------
banner "CHECK 7: Port 8080 availability"

PORT_PID=""
if command -v lsof &>/dev/null; then
  PORT_PID=$(lsof -ti tcp:8080 2>/dev/null | head -1 || true)
elif command -v ss &>/dev/null; then
  PORT_PID=$(ss -tlnp 'sport = :8080' 2>/dev/null \
    | awk 'NR>1 && /LISTEN/{match($0,/pid=([0-9]+)/,a); print a[1]}' | head -1 || true)
fi

if [[ -z "${PORT_PID}" ]]; then
  ok "Port 8080 is free"
else
  PROC_NAME=$(ps -p "${PORT_PID}" -o comm= 2>/dev/null || true)

  PORT_IS_CRAPI=false
  if [[ -f "${COMPOSE_FILE}" ]]; then
    CRAPI_IDENTITY_CID=$(docker compose -f "${COMPOSE_FILE}" ps -q crapi-identity 2>/dev/null || true)
    if [[ -n "${CRAPI_IDENTITY_CID}" ]]; then
      MAPPED=$(docker inspect "${CRAPI_IDENTITY_CID}" --format '{{json .NetworkSettings.Ports}}' \
        2>/dev/null | grep -c '"8080/tcp"' || true)
      [[ "${MAPPED}" -gt 0 ]] && PORT_IS_CRAPI=true
    fi
  fi

  if [[ "${PORT_IS_CRAPI}" == "true" ]]; then
    ok "Port 8080 is in use by crapi-identity Docker container (run-whitebox.sh will stop it)"
  else
    warn "Port 8080 is in use by PID ${PORT_PID} (${PROC_NAME:-unknown}) — this may conflict with the instrumented JAR"
  fi
fi

# ---------------------------------------------------------------------------
# CHECK 8: Java version
# ---------------------------------------------------------------------------
banner "CHECK 8: Java version"

if ! command -v java &>/dev/null; then
  fail "java not found in PATH"
else
  JAVA_BIN=$(command -v java)
  JAVA_VERSION_OUTPUT=$(java -version 2>&1 | head -1)
  JAVA_MAJOR=$(awk -F '"' '/version/ {split($2,a,"."); if (a[1]=="1") print a[2]; else print a[1]}' \
    <<< "${JAVA_VERSION_OUTPUT}" | tr -d '[:space:]')
  if [[ -n "${JAVA_MAJOR}" ]] && [[ "${JAVA_MAJOR}" -ge 17 ]]; then
    ok "Java ${JAVA_MAJOR} (>= 17) at ${JAVA_BIN}"
    ok "  Version string: ${JAVA_VERSION_OUTPUT}"
  else
    fail "Java ${JAVA_MAJOR} is below the required minimum of 17 (found: ${JAVA_VERSION_OUTPUT})"
  fi
fi

# ---------------------------------------------------------------------------
# CHECK 9: em.yaml parse validation
# ---------------------------------------------------------------------------
banner "CHECK 9: em.yaml parse validation"

EM_YAML="${REPO_ROOT}/em.yaml"
if [[ ! -f "${EM_YAML}" ]]; then
  fail "em.yaml not found at ${EM_YAML}"
elif [[ -z "${EVOMASTER_JAR}" ]]; then
  warn "Skipping em.yaml validation — evomaster.jar not available (CHECK 1 failed)"
else
  # Run EvoMaster with the config; it will fail because the driver isn't running,
  # but YAML parse errors appear before the driver-connection error and match this pattern.
  YAML_ERRORS=$(java -jar "${EVOMASTER_JAR}" --configPath "${EM_YAML}" 2>&1 \
    | grep -iE "Failed (when reading|to parse) config|Invalid parameter settings.*config|cannot deserialize" \
    || true)
  if [[ -n "${YAML_ERRORS}" ]]; then
    fail "em.yaml has parse errors:"
    while IFS= read -r line; do
      hint "${line}"
    done <<< "${YAML_ERRORS}"
  else
    ok "em.yaml parsed without errors"
  fi
fi

# ---------------------------------------------------------------------------
# CHECK 10: Driver JAR freshness
# ---------------------------------------------------------------------------
banner "CHECK 10: Driver JAR freshness"

if [[ ! -f "${DRIVER_JAR}" ]]; then
  warn "Skipping freshness check — driver JAR not found (CHECK 3 failed)"
else
  SRC_DIR="${REPO_ROOT}/evomaster-driver/src"
  if [[ ! -d "${SRC_DIR}" ]]; then
    warn "Source directory not found: ${SRC_DIR} — skipping freshness check"
  else
    STALE_SRC=$(find "${SRC_DIR}" -name "*.java" -newer "${DRIVER_JAR}" -print -quit 2>/dev/null || true)
    if [[ -n "${STALE_SRC}" ]]; then
      warn "Driver JAR may be stale — newer source file found: ${STALE_SRC}"
      hint "Rebuild with: cd evomaster-driver && mvn package -DskipTests"
    else
      JAR_MTIME=$(get_mtime "${DRIVER_JAR}")
      if [[ "${JAR_MTIME}" -eq 0 ]]; then
        warn "No .java source files found in ${SRC_DIR}"
      else
        ok "Driver JAR is up to date (newer than all source files)"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD}  Preflight Check Summary${RESET}"
echo -e "${BOLD}============================================================${RESET}"
echo -e "  ${GREEN}Passed${RESET}:  ${OK_COUNT} checks OK"
echo -e "  ${YELLOW}Warned${RESET}:  ${WARN_COUNT} checks with warnings"
echo -e "  ${RED}Failed${RESET}:  ${FAIL_COUNT} checks"
echo

if [[ "${FAIL_COUNT}" -eq 0 ]]; then
  echo -e "  ${GREEN}${BOLD}All required checks passed. Ready to run run-whitebox.sh.${RESET}"
  echo
  exit 0
else
  echo -e "  ${RED}${BOLD}${FAIL_COUNT} check(s) FAILED. Fix the issues above before running run-whitebox.sh.${RESET}"
  echo
  exit 1
fi
