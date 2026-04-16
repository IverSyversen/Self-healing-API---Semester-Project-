#!/usr/bin/env bash
# =============================================================================
# run-whitebox.sh
#
# Orchestrates an EvoMaster white-box test-generation run against the crAPI
# identity service.
#
# Steps:
#   1.  Start the full crAPI Docker stack (all services including community)
#       so that MongoDB and dependent services are available.
#   2.  Stop the Docker-managed identity service container so its port is free.
#   3.  Start the EvoMaster driver (CrApiCommunityController) in the background.
#       The driver will spawn the identity service JAR with the EvoMaster agent.
#   4.  Run the EvoMaster CLI in white-box mode.
#   5.  Print the location of the generated test suite.
#   6.  Stop the driver and restore the Docker identity service (optional).
#
# Usage:
#   bash scripts/run-whitebox.sh [--time <minutes>] [--output <dir>]
#
# Options:
#   --time    <minutes>   Budget for EvoMaster test generation (default: 60)
#   --output  <dir>       Directory to write generated tests (default: ./generated_tests)
#   --no-restore          Do not restart the Docker identity service after the run
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TIME_BUDGET_MINUTES=60
OUTPUT_DIR="$(pwd)/generated_tests"
RESTORE_COMMUNITY=true
SEED_FILE=""
SEED_FORMAT="POSTMAN"
SEED=12345

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

EVOMASTER_DIR="/opt/evomaster"
EVOMASTER_CLI="${EVOMASTER_DIR}/evomaster.jar"
EVOMASTER_AGENT="${EVOMASTER_DIR}/evomaster-agent.jar"
IDENTITY_JAR="/opt/crapi/identity-service.jar"
DRIVER_JAR="${REPO_ROOT}/evomaster-driver/target/crapi-community-driver-1.0.0.jar"

DRIVER_PORT=40100
SUT_PORT=8080
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="crapi"
DB_USER="admin"
DB_PASS="crapisecretpassword"
JWKS_FILE="/opt/crapi/jwks.json"
EM_XMS="${EM_XMS:-256m}"
EM_XMX="${EM_XMX:-1024m}"
RESET_MONGO="${RESET_MONGO:-false}"
SEED_USERS="${SEED_USERS:-true}"
EM_EXPERIMENTAL="${EM_EXPERIMENTAL:-false}"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --time)        TIME_BUDGET_MINUTES="$2"; shift 2 ;;
    --output)      OUTPUT_DIR="$2";          shift 2 ;;
    --seed-file)   SEED_FILE="$2";           shift 2 ;;
    --seed-format) SEED_FORMAT="$2";         shift 2 ;;
    --seed)        SEED="$2";                shift 2 ;;
    --no-restore)  RESTORE_COMMUNITY=false;  shift   ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Auto-detect the crAPI Postman collection installed by setup-droplet.sh.
# The collection is sanitized during setup (sanitize-postman.sh patches null
# response arrays that would otherwise NPE in EvoMaster 3.3.0's PostmanParser).
# Pass --seed-file explicitly to override, or --seed-file "" to disable.
# POSTMAN SEEDING DISABLED FOR NOW
if [[ -z "${SEED_FILE}" ]]; then
  SEED_FILE=""
  # if [[ -s /opt/crapi/postman/crapi.postman_collection.json ]]; then
  #   SEED_FILE=/opt/crapi/postman/crapi.postman_collection.json
  #   SEED_FORMAT=POSTMAN
  # fi
fi

TIME_BUDGET="${TIME_BUDGET_MINUTES}m"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo "[INFO]  $*"; }
warning() { echo "[WARN]  $*" >&2; }
error()   { echo "[ERROR] $*" >&2; }

DRIVER_PID=""

kill_host_identity_processes() {
  local pids=()
  mapfile -t pids < <(
    ps -eo pid=,args= \
      | awk -v sut_port="${SUT_PORT}" '
          $0 ~ /[j]ava/ &&
          $0 ~ /\/opt\/crapi\/identity-service\.jar/ &&
          index($0, "--server.port=" sut_port) > 0 {print $1}
        '
  )

  for pid in "${pids[@]}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      warning "Stopping stale host identity-service.jar process on port ${SUT_PORT} (PID ${pid})…"
      kill "${pid}" || true
      sleep 1
      if kill -0 "${pid}" 2>/dev/null; then
        warning "Process ${pid} did not exit after SIGTERM; sending SIGKILL."
        kill -9 "${pid}" || true
      fi
    fi
  done
}

port_is_listening() {
  local port="$1"
  ss -ltn "sport = :${port}" 2>/dev/null | awk 'NR>1 {found=1} END {exit(found ? 0 : 1)}'
}

choose_driver_port() {
  local start_port="$1"
  local max_tries=25
  local candidate
  for ((i=0; i<max_tries; i++)); do
    candidate=$((start_port + i))
    if ! port_is_listening "${candidate}"; then
      if [[ "${candidate}" != "${DRIVER_PORT}" ]]; then
        warning "Driver port ${DRIVER_PORT} is busy; using ${candidate} instead."
      fi
      DRIVER_PORT="${candidate}"
      return
    fi
  done
  error "No free driver port found in range ${start_port}-$((start_port + max_tries - 1))."
  exit 1
}

cleanup() {
  info "Cleaning up…"
  if [[ -n "${DRIVER_PID}" ]] && kill -0 "${DRIVER_PID}" 2>/dev/null; then
    info "Stopping EvoMaster driver (PID ${DRIVER_PID})…"
    kill "${DRIVER_PID}" || true
  fi
  kill_host_identity_processes
  if [[ "${RESTORE_COMMUNITY}" == "true" ]]; then
    info "Restoring Docker identity service…"
    docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" up -d crapi-identity \
      || warning "Could not restart the identity service Docker container."
  fi
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
for f in "${EVOMASTER_CLI}" "${EVOMASTER_AGENT}" "${IDENTITY_JAR}" "${DRIVER_JAR}" "${JWKS_FILE}"; do
  if [[ ! -f "${f}" ]]; then
    error "Required file not found: ${f}"
    error "Run scripts/setup-droplet.sh first."
    exit 1
  fi
done

if ! command -v docker &>/dev/null; then
  error "Docker not found. Install Docker and re-run."
  exit 1
fi

# ---------------------------------------------------------------------------
# 1. Ensure only infra dependencies are running for white-box mode.
#    Running the full stack while stopping containerized identity causes
#    restart loops in dependent services and destabilizes local resources.
# ---------------------------------------------------------------------------
info "Starting required infra services (postgres, mongodb, mailhog)…"
docker compose \
  -f "${REPO_ROOT}/docker-compose.evomaster.yml" \
  up -d --remove-orphans postgres mongodb mailhog

# Stop service containers that depend on Docker-managed identity. White-box mode
# runs identity-service.jar on the host instead.
docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" stop \
  crapi-web crapi-workshop crapi-community crapi-identity >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 2. Stop the Docker-managed identity service so we can claim port ${SUT_PORT}.
# ---------------------------------------------------------------------------
info "Stopping Docker identity service container (port ${SUT_PORT} must be free)…"
docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" stop crapi-identity \
  || warning "crapi-identity container was not running – that is fine."

# If a previous run terminated unexpectedly, the host-based identity-service.jar
# can be left behind and keep port ${SUT_PORT} occupied.
kill_host_identity_processes

# Pick a free local driver port to avoid collisions with concurrent/stale runs.
choose_driver_port "${DRIVER_PORT}"

# ---------------------------------------------------------------------------
# 3. Start the EvoMaster driver in the background.
#    The driver spawns the community service JAR with the agent attached.
# ---------------------------------------------------------------------------
mkdir -p "${OUTPUT_DIR}"

# Start the driver with retries: another parallel run can claim the same port
# in the short window between our free-port probe and the actual bind.
DRIVER_READY=false
for attempt in $(seq 1 6); do
  info "Starting EvoMaster driver on port ${DRIVER_PORT}…"
  java \
    -Dsut.jar="${IDENTITY_JAR}" \
    -Devomaster.instrumentation.jar.path="${EVOMASTER_AGENT}" \
    -Ddb.host="${DB_HOST}" \
    -Ddb.port="${DB_PORT}" \
    -Ddb.name="${DB_NAME}" \
  -Ddb.user="${DB_USER}" \
  -Ddb.password="${DB_PASS}" \
  -Dreset.mongo="${RESET_MONGO}" \
  -Dseed.users="${SEED_USERS}" \
  -Ddriver.disable.sql.spec=true \
    -Dopenapi.url="https://raw.githubusercontent.com/OWASP/crAPI/main/openapi-spec/crapi-openapi-spec.json" \
    -jar "${DRIVER_JAR}" "${DRIVER_PORT}" \
    > "${OUTPUT_DIR}/driver.log" 2>&1 &
  DRIVER_PID=$!

  info "Driver PID: ${DRIVER_PID}  (logs: ${OUTPUT_DIR}/driver.log)"
  info "Waiting for EvoMaster driver to be ready…"

  for _ in $(seq 1 60); do
    if (echo >/dev/tcp/localhost/${DRIVER_PORT}) 2>/dev/null; then
      info "Driver is ready."
      DRIVER_READY=true
      break
    fi
    if ! kill -0 "${DRIVER_PID}" 2>/dev/null; then
      break
    fi
    sleep 3
  done

  if [[ "${DRIVER_READY}" == "true" ]]; then
    break
  fi

  if kill -0 "${DRIVER_PID}" 2>/dev/null; then
    kill "${DRIVER_PID}" || true
  fi
  DRIVER_PID=""

  if grep -q "Failed to bind to localhost/127.0.0.1:${DRIVER_PORT}" "${OUTPUT_DIR}/driver.log" 2>/dev/null; then
    warning "Driver port ${DRIVER_PORT} was claimed concurrently; retrying on next port."
    DRIVER_PORT=$((DRIVER_PORT + 1))
    continue
  fi

  error "EvoMaster driver failed to become ready on port ${DRIVER_PORT}."
  error "Check ${OUTPUT_DIR}/driver.log for details."
  exit 1
done

if [[ "${DRIVER_READY}" != "true" ]]; then
  error "EvoMaster driver failed to start after multiple port retries."
  error "Check ${OUTPUT_DIR}/driver.log for details."
  exit 1
fi

# ---------------------------------------------------------------------------
# 4. Run EvoMaster CLI in white-box mode.
#
# Flag rationale (tuned specifically for crAPI security testing):
#   --security true
#       Turns on EvoMaster's REST security oracles (missing auth, forbidden
#       bypass, inconsistent 401/403, BOLA/BOPLA detection across seeded users).
#   --schemaOracles true
#       Flags responses whose status code or Content-Type is NOT documented in
#       the OpenAPI spec — this is what caught F-01..F-08 in the first run.
#   --expectationsActive true
#       Emits JUnit assertions based on observed behaviour so the generated
#       test suite fails loudly if the behaviour regresses.
#   --taintOnSampling true
#       Enables string/int taint propagation even for brand-new samples; helps
#       solve conditions like "if (email.equalsIgnoreCase(\"admin@…\"))".
#   --discoveredInfoRewardedInFitness true
#       Rewards individuals that uncover new JSON response fields, which is
#       exactly the signal needed to discover mass-assignment bugs.
#   --advancedBlackBoxCoverage true
#       Keeps black-box-equivalent coverage metrics alongside white-box ones,
#       which produces more complete statistics for the final report.
#   --writeSnapshot / --writeStatistics / --writeWFCReportFormat / --exportCoveredTarget
#       Diagnostic dumps read by run-report.sh to annotate the HTML report.
#   --seedTestCases*
#       Seeds mutation with real example requests from a Postman collection
#       (or OpenAPI `examples` section), dramatically improving the rate at
#       which EvoMaster hits valid state-dependent flows on crAPI.
# ---------------------------------------------------------------------------
SEED_ARGS=()
if [[ -n "${SEED_FILE}" && -f "${SEED_FILE}" ]]; then
  info "Seeding EvoMaster with ${SEED_FORMAT} collection: ${SEED_FILE}"
  SEED_ARGS=(--seedTestCases true --seedTestCasesPath "${SEED_FILE}" --seedTestCasesFormat "${SEED_FORMAT}")
else
  info "No seed collection – explicitly disabling seedTestCases to override any cached em.yaml value."
  # EvoMaster persists CLI flags to em.yaml between runs.  If a previous run
  # stored seedTestCasesPath there, EvoMaster will replay it even when we omit
  # the flag.  Passing --seedTestCases false forces it off regardless of the
  # cached config.
  SEED_ARGS=(--seedTestCases false)
fi

info "Starting EvoMaster white-box test generation (budget: ${TIME_BUDGET})…"
EXPERIMENTAL_ARGS=()
if [[ "${EM_EXPERIMENTAL}" == "true" ]]; then
  EXPERIMENTAL_ARGS=(
    --security true
    --schemaOracles true
    --expectationsActive true
    --taintOnSampling true
    --discoveredInfoRewardedInFitness true
    --advancedBlackBoxCoverage true
    --enableWriteSnapshotTests true
    --writeStatistics true
    --exportCoveredTarget true
  )
fi

java -Xms"${EM_XMS}" -Xmx"${EM_XMX}" -jar "${EVOMASTER_CLI}" \
  --blackBox false \
  --problemType REST \
  --sutControllerHost localhost \
  --sutControllerPort "${DRIVER_PORT}" \
  --maxTime "${TIME_BUDGET}" \
  --outputFolder "${OUTPUT_DIR}" \
  --outputFormat JAVA_JUNIT_5 \
  --outputFilePrefix CrApiCommunityEvoMasterTest \
  --enableBasicAssertions true \
  "${EXPERIMENTAL_ARGS[@]}" \
  --seed "${SEED}" \
  "${SEED_ARGS[@]}"

# ---------------------------------------------------------------------------
# 5. Report results.
# ---------------------------------------------------------------------------
info "===================================================================="
info "Test generation complete."
info "Generated tests are in: ${OUTPUT_DIR}"
info ""
info "To compile and view the HTML report:"
info "  bash scripts/run-report.sh --tests-dir ${OUTPUT_DIR}"
info "===================================================================="
