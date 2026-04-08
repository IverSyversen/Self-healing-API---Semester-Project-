#!/usr/bin/env bash
# =============================================================================
# run-whitebox.sh
#
# Orchestrates an EvoMaster white-box test-generation run against the crAPI
# community service.
#
# Steps:
#   1.  Start the full crAPI Docker stack (minus community service) so that
#       MongoDB and dependent services are available.
#   2.  Stop the Docker-managed community service container so its port is free.
#   3.  Start the EvoMaster driver (CrApiCommunityController) in the background.
#       The driver will spawn the community service JAR with the EvoMaster agent.
#   4.  Run the EvoMaster CLI in white-box mode.
#   5.  Print the location of the generated test suite.
#   6.  Stop the driver and restore the Docker community service (optional).
#
# Usage:
#   bash scripts/run-whitebox.sh [--time <minutes>] [--output <dir>]
#
# Options:
#   --time    <minutes>   Budget for EvoMaster test generation (default: 60)
#   --output  <dir>       Directory to write generated tests (default: ./generated_tests)
#   --no-restore          Do not restart the Docker community service after the run
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
TIME_BUDGET_MINUTES=60
OUTPUT_DIR="$(pwd)/generated_tests"
RESTORE_COMMUNITY=true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

EVOMASTER_DIR="/opt/evomaster"
EVOMASTER_CLI="${EVOMASTER_DIR}/evomaster.jar"
EVOMASTER_AGENT="${EVOMASTER_DIR}/evomaster-agent.jar"
COMMUNITY_JAR="/opt/crapi/community-service.jar"
DRIVER_JAR="${REPO_ROOT}/evomaster-driver/target/crapi-community-driver-1.0.0.jar"

DRIVER_PORT=40100
SUT_PORT=8087
MONGO_URI="mongodb://localhost:27017/crapi"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --time)      TIME_BUDGET_MINUTES="$2"; shift 2 ;;
    --output)    OUTPUT_DIR="$2";          shift 2 ;;
    --no-restore) RESTORE_COMMUNITY=false; shift   ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

TIME_BUDGET="${TIME_BUDGET_MINUTES}m"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo "[INFO]  $*"; }
warning() { echo "[WARN]  $*" >&2; }
error()   { echo "[ERROR] $*" >&2; }

DRIVER_PID=""

cleanup() {
  info "Cleaning up…"
  if [[ -n "${DRIVER_PID}" ]] && kill -0 "${DRIVER_PID}" 2>/dev/null; then
    info "Stopping EvoMaster driver (PID ${DRIVER_PID})…"
    kill "${DRIVER_PID}" || true
  fi
  if [[ "${RESTORE_COMMUNITY}" == "true" ]]; then
    info "Restoring Docker community service…"
    docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" up -d crapi-community \
      || warning "Could not restart the community service Docker container."
  fi
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
for f in "${EVOMASTER_CLI}" "${EVOMASTER_AGENT}" "${COMMUNITY_JAR}" "${DRIVER_JAR}"; do
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
# 1. Ensure the crAPI stack is running (databases + all services except community)
# ---------------------------------------------------------------------------
info "Starting crAPI Docker stack (without community service)…"
LISTEN_IP="0.0.0.0" docker compose \
  -f "${REPO_ROOT}/docker-compose.evomaster.yml" \
  up -d --remove-orphans

# Give services a moment to initialise.
info "Waiting 15 s for services to initialise…"
sleep 15

# ---------------------------------------------------------------------------
# 2. Stop the Docker-managed community service so we can claim port ${SUT_PORT}.
# ---------------------------------------------------------------------------
info "Stopping Docker community service container (port ${SUT_PORT} must be free)…"
docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" stop crapi-community \
  || warning "crapi-community container was not running – that is fine."

# ---------------------------------------------------------------------------
# 3. Start the EvoMaster driver in the background.
#    The driver spawns the community service JAR with the agent attached.
# ---------------------------------------------------------------------------
mkdir -p "${OUTPUT_DIR}"

info "Starting EvoMaster driver on port ${DRIVER_PORT}…"
java \
  -Dsut.jar="${COMMUNITY_JAR}" \
  -Dagent.jar="${EVOMASTER_AGENT}" \
  -Dmongo.uri="${MONGO_URI}" \
  -Dopenapi.url="http://localhost:${SUT_PORT}/v3/api-docs" \
  -jar "${DRIVER_JAR}" "${DRIVER_PORT}" \
  > "${OUTPUT_DIR}/driver.log" 2>&1 &
DRIVER_PID=$!

info "Driver PID: ${DRIVER_PID}  (logs: ${OUTPUT_DIR}/driver.log)"

# Wait until the driver REST API is reachable.
info "Waiting for EvoMaster driver to be ready…"
for _ in $(seq 1 60); do
  if curl -sf "http://localhost:${DRIVER_PORT}/api/infoSUT" > /dev/null 2>&1; then
    info "Driver is ready."
    break
  fi
  if ! kill -0 "${DRIVER_PID}" 2>/dev/null; then
    error "EvoMaster driver process died unexpectedly."
    error "Check ${OUTPUT_DIR}/driver.log for details."
    exit 1
  fi
  sleep 3
done

# ---------------------------------------------------------------------------
# 4. Run EvoMaster CLI in white-box mode.
# ---------------------------------------------------------------------------
info "Starting EvoMaster white-box test generation (budget: ${TIME_BUDGET})…"
java -jar "${EVOMASTER_CLI}" \
  --blackBox false \
  --sutControllerHost localhost \
  --sutControllerPort "${DRIVER_PORT}" \
  --maxTime "${TIME_BUDGET}" \
  --outputFolder "${OUTPUT_DIR}" \
  --outputFormat JAVA_JUNIT_5 \
  --testSuiteFileName CrApiCommunityEvoMasterTest \
  --coveredTargetSortedBy EXECUTION_INDEX \
  --enableBasicAssertions true \
  --seed 12345

# ---------------------------------------------------------------------------
# 5. Report results.
# ---------------------------------------------------------------------------
info "===================================================================="
info "Test generation complete."
info "Generated tests are in: ${OUTPUT_DIR}"
info ""
info "To view the HTML report:"
info "  cd ${OUTPUT_DIR} && python3 -m http.server 8000"
info "  Open http://localhost:8000 in a browser."
info "===================================================================="
