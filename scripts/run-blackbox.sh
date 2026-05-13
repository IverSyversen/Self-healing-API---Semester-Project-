#!/usr/bin/env bash
# =============================================================================
# run-blackbox.sh
#
# Orchestrates a full EvoMaster black-box test-generation run against crAPI via
# the web gateway (default: http://localhost:8888).
#
# Usage:
#   bash scripts/run-blackbox.sh [--time <minutes>] [--output <dir>]
#                                [--target-url <url>] [--swagger-url <url>]
#                                [--seed-file <path>] [--seed-format <format>]
#                                [--seed <int>] [--no-stack-start] [--reset-data]
#
# Options:
#   --time          <minutes>  Budget for EvoMaster generation (default: 120)
#   --output        <dir>      Output directory for generated tests
#   --target-url    <url>      Base URL of crAPI gateway (default: http://localhost:8888)
#   --swagger-url   <url>      OpenAPI URL/file (default: file://.../postman/crapi-openapi-spec-patched.json)
#   --seed-file     <path>     Optional seed corpus (Postman/OpenAPI examples)
#   --seed-format   <format>   Seed format for EvoMaster (default: POSTMAN)
#   --seed          <int>      Fixed RNG seed for reproducibility
#   --no-stack-start            Do not start docker-compose stack automatically
#   --reset-data                Recreate docker volumes for a clean crAPI dataset
# =============================================================================
set -euo pipefail

TIME_BUDGET_MINUTES=120
OUTPUT_DIR="$(pwd)/generated_tests_blackbox"
TARGET_URL="${TARGET_URL:-http://localhost:8888}"
AUTO_REPORT="${AUTO_REPORT:-true}"
START_STACK=true
RESET_DATA=false
SEED_FILE=""
SEED_FORMAT="POSTMAN"
SEED=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PATCHED_SPEC="${REPO_ROOT}/postman/crapi-openapi-spec-patched.json"
SWAGGER_URL="${SWAGGER_URL:-file://${PATCHED_SPEC}}"

if [[ -z "${EVOMASTER_DIR:-}" ]]; then
  for _em_candidate in \
      "${HOME}/evomaster" \
      /opt/evomaster \
      "${HOME}/.local/evomaster"; do
    if [[ -f "${_em_candidate}/evomaster.jar" ]]; then
      EVOMASTER_DIR="${_em_candidate}"
      break
    fi
  done
  EVOMASTER_DIR="${EVOMASTER_DIR:-/opt/evomaster}"
fi

EVOMASTER_CLI="${EVOMASTER_DIR}/evomaster.jar"
EM_XMS="${EM_XMS:-256m}"
EM_XMX="${EM_XMX:-2048m}"
JAVA_BIN="${JAVA_BIN:-}"

info()    { echo "[INFO]  $*"; }
warning() { echo "[WARN]  $*" >&2; }
error()   { echo "[ERROR] $*" >&2; }

EM_PID=""
INTERRUPTED_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --time)          TIME_BUDGET_MINUTES="$2"; shift 2 ;;
    --output)        OUTPUT_DIR="$2";          shift 2 ;;
    --target-url)    TARGET_URL="$2";          shift 2 ;;
    --swagger-url)   SWAGGER_URL="$2";         shift 2 ;;
    --seed-file)     SEED_FILE="$2";           shift 2 ;;
    --seed-format)   SEED_FORMAT="$2";         shift 2 ;;
    --seed)          SEED="$2";                shift 2 ;;
    --no-stack-start) START_STACK=false;       shift   ;;
    --reset-data)    RESET_DATA=true;          shift   ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

resolve_java_bin() {
  if [[ -n "${JAVA_BIN}" ]]; then
    return
  fi
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    local java21_home=""
    java21_home="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
    if [[ -n "${java21_home}" && -x "${java21_home}/bin/java" ]]; then
      JAVA_BIN="${java21_home}/bin/java"
      return
    fi
  fi
  JAVA_BIN="$(command -v java)"
}

wait_for_http() {
  local url="$1"
  local attempts=120
  info "Waiting for target to be reachable: ${url}"
  for _ in $(seq 1 "${attempts}"); do
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${url}" || true)"
    if [[ "${code}" =~ ^[1-5][0-9][0-9]$ ]]; then
      info "Target reachable (HTTP ${code})."
      return 0
    fi
    sleep 2
  done
  error "Target did not become reachable: ${url}"
  return 1
}

on_interrupt() {
  if [[ -n "${EM_PID}" ]] && kill -0 "${EM_PID}" 2>/dev/null; then
    warning "Interrupt received. Asking EvoMaster to stop gracefully and write output..."
    INTERRUPTED_RUN=true
    kill -INT "${EM_PID}" 2>/dev/null || true
    return
  fi
  exit 130
}
trap on_interrupt INT TERM

if [[ -z "${SEED_FILE}" ]]; then
  for _postman_candidate in \
      "${REPO_ROOT}/postman/crapi.postman_collection.json" \
      "/opt/crapi/postman/crapi.postman_collection.json"; do
    if [[ -s "${_postman_candidate}" ]]; then
      info "Auto-detected Postman collection: ${_postman_candidate}"
      SANITIZED_POSTMAN="$(mktemp -t crapi-postman-sanitized.XXXXXX)"
      bash "${SCRIPT_DIR}/sanitize-postman.sh" "${_postman_candidate}" "${SANITIZED_POSTMAN}"
      SEED_FILE="${SANITIZED_POSTMAN}"
      SEED_FORMAT="POSTMAN"
      break
    fi
  done
fi

resolve_java_bin

for f in "${EVOMASTER_CLI}"; do
  if [[ ! -f "${f}" ]]; then
    error "Required file not found: ${f}"
    error "Run scripts/download-evomaster.sh first."
    exit 1
  fi
done

if [[ -z "${JAVA_BIN}" || ! -x "${JAVA_BIN}" ]]; then
  error "Could not resolve a usable Java runtime."
  exit 1
fi
info "Using Java runtime: ${JAVA_BIN}"

if [[ "${START_STACK}" == "true" ]]; then
  if [[ "${RESET_DATA}" == "true" ]]; then
    info "Resetting Docker volumes for a clean crAPI dataset..."
    docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" down -v
  fi
  info "Starting full crAPI stack for black-box run..."
  docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" \
    up -d postgres mongodb mailhog crapi-identity crapi-workshop crapi-community crapi-web
fi

wait_for_http "${TARGET_URL}"

mkdir -p "${OUTPUT_DIR}"
find "${OUTPUT_DIR}" -maxdepth 1 -type f \
  \( -name 'CrApiBlackBoxEvoMasterTest*.java' -o -name 'index.html' -o -name 'report.json' -o -name 'surefire-report.html' \) \
  -delete 2>/dev/null || true

TIME_BUDGET="${TIME_BUDGET_MINUTES}m"
SEED_ARGS=()
if [[ -n "${SEED_FILE}" && -f "${SEED_FILE}" ]]; then
  info "Seeding EvoMaster with ${SEED_FORMAT}: ${SEED_FILE}"
  SEED_ARGS=(--seedTestCases true --seedTestCasesPath "${SEED_FILE}" --seedTestCasesFormat "${SEED_FORMAT}")
else
  SEED_ARGS=(--seedTestCases false)
fi

SEED_VALUE_ARGS=()
if [[ -n "${SEED}" ]]; then
  info "Using fixed random seed: ${SEED}"
  SEED_VALUE_ARGS=(--seed "${SEED}")
fi

HEADER_ARGS=()
if [[ -n "${EM_HEADER0:-}" ]]; then HEADER_ARGS+=(--header0 "${EM_HEADER0}"); fi
if [[ -n "${EM_HEADER1:-}" ]]; then HEADER_ARGS+=(--header1 "${EM_HEADER1}"); fi
if [[ -n "${EM_HEADER2:-}" ]]; then HEADER_ARGS+=(--header2 "${EM_HEADER2}"); fi

EM_LOG="${OUTPUT_DIR}/evomaster.log"
info "Starting EvoMaster black-box run (budget: ${TIME_BUDGET})..."

set +u
set +e
"${JAVA_BIN}" -Xms"${EM_XMS}" -Xmx"${EM_XMX}" -jar "${EVOMASTER_CLI}" \
  --blackBox true \
  --problemType REST \
  --bbTargetUrl "${TARGET_URL}" \
  --bbSwaggerUrl "${SWAGGER_URL}" \
  --maxTime "${TIME_BUDGET}" \
  --outputFolder "${OUTPUT_DIR}" \
  --outputFormat JAVA_JUNIT_5 \
  --outputFilePrefix CrApiBlackBoxEvoMasterTest \
  --enableBasicAssertions true \
  --security true \
  --schemaOracles true \
  --taintOnSampling true \
  --discoveredInfoRewardedInFitness true \
  --advancedBlackBoxCoverage true \
  --expectationsActive true \
  --writeStatistics true \
  --exportCoveredTarget true \
  --extraPhaseBudgetPercentage 0.4 \
  --minimizeTimeout 3 \
  "${SEED_VALUE_ARGS[@]}" \
  "${SEED_ARGS[@]}" \
  "${HEADER_ARGS[@]}" > >(tee "${EM_LOG}") 2>&1 &
EM_PID=$!

while true; do
  wait "${EM_PID}"
  EM_EXIT=$?
  if [[ "${EM_EXIT}" -ge 128 ]] && kill -0 "${EM_PID}" 2>/dev/null; then
    continue
  fi
  break
done
EM_PID=""
set -e
set -u

if [[ "${EM_EXIT}" -ne 0 ]]; then
  error "EvoMaster exited with ${EM_EXIT}. Logs: ${EM_LOG}"
  if [[ "${INTERRUPTED_RUN}" == "true" ]]; then
    warning "Run was interrupted by user signal."
  fi
fi

GENERATED_SOURCES=( "${OUTPUT_DIR}"/CrApiBlackBoxEvoMasterTest*.java )
if [[ "${AUTO_REPORT}" == "true" && -f "${GENERATED_SOURCES[0]}" ]]; then
  info "Generating HTML report from current generated tests..."
  bash "${SCRIPT_DIR}/run-report.sh" --tests-dir "${OUTPUT_DIR}" --sut-base-url "${TARGET_URL}" \
    || warning "run-report.sh failed. Check logs above."
fi

if [[ -n "${SANITIZED_POSTMAN:-}" && -f "${SANITIZED_POSTMAN:-}" ]]; then
  rm -f "${SANITIZED_POSTMAN}"
fi

if [[ "${EM_EXIT}" -ne 0 ]]; then
  exit "${EM_EXIT}"
fi

info "===================================================================="
info "Black-box generation complete."
info "Generated tests are in: ${OUTPUT_DIR}"
info "===================================================================="
