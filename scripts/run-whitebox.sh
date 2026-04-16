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

# NOTE: Auto-detection of the crAPI Postman collection has been disabled.
# EvoMaster 3.3.0 has a bug in PostmanParser.parseTestCases (PostmanParser.kt:172)
# where it throws a NullPointerException when the collection contains items with
# null response arrays (common in the OWASP crAPI default collection).  Until
# that upstream bug is fixed, Postman seeding must be opted in explicitly via
# the --seed-file flag with a collection that has been sanitised.
# To re-enable: bash scripts/run-whitebox.sh --seed-file /path/to/collection.json

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
# 1. Ensure the crAPI stack is running (all services; identity will be stopped next)
# ---------------------------------------------------------------------------
info "Starting crAPI Docker stack…"
docker compose \
  -f "${REPO_ROOT}/docker-compose.evomaster.yml" \
  up -d --remove-orphans

# Wait until the crapi-identity container has fully started and seeded the
# vehicle catalog (vehicle_company / vehicle_model tables).
#
# Strategy (avoids a hard fixed sleep):
#   1. Poll Docker logs for the "Started CRAPIBootApplication" banner.
#      Max wait: 90 s (18 × 5 s).  Spring Boot typically prints this in <40 s.
#   2. Once the banner appears, poll the identity service's HTTP login endpoint
#      until it responds (any HTTP status) – this confirms the HTTP server is
#      actually accepting connections and InitialDataConfig has finished running.
#      Max extra wait: 30 s (30 × 1 s).
info "Waiting for crAPI identity service to become ready (up to 90 s)…"
IDENTITY_READY=false
for _ in $(seq 1 18); do
  if docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" logs --no-follow crapi-identity 2>/dev/null \
      | grep -q "Started CRAPIBootApplication"; then
    IDENTITY_READY=true
    break
  fi
  sleep 5
done

if [[ "${IDENTITY_READY}" == "true" ]]; then
  info "crAPI identity service banner seen; waiting for HTTP endpoint to accept connections…"
  HTTP_UP=false
  for _ in $(seq 1 30); do
    # Any HTTP response (even 400/401/500) means the server is up and
    # seeding is done.  -s = silent, no -f so we don't fail on 4xx/5xx.
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
         "http://localhost:${SUT_PORT}/identity/api/auth/login" \
         -X POST -H "Content-Type: application/json" -d '{}' 2>/dev/null || true)
    if [[ "${HTTP_CODE}" =~ ^[0-9]{3}$ ]]; then
      HTTP_UP=true
      break
    fi
    sleep 1
  done
  if [[ "${HTTP_UP}" == "true" ]]; then
    info "crAPI identity service is accepting HTTP connections."
  else
    info "HTTP endpoint did not respond within 30 s; proceeding anyway…"
  fi
else
  warning "crAPI identity service did not start within 90 s; proceeding anyway…"
fi

# ---------------------------------------------------------------------------
# 2. Stop the Docker-managed identity service so we can claim port ${SUT_PORT}.
# ---------------------------------------------------------------------------
info "Stopping Docker identity service container (port ${SUT_PORT} must be free)…"
docker compose -f "${REPO_ROOT}/docker-compose.evomaster.yml" stop crapi-identity \
  || warning "crapi-identity container was not running – that is fine."

# ---------------------------------------------------------------------------
# 3. Start the EvoMaster driver in the background.
#    The driver spawns the community service JAR with the agent attached.
# ---------------------------------------------------------------------------
mkdir -p "${OUTPUT_DIR}"

info "Starting EvoMaster driver on port ${DRIVER_PORT}…"
java \
  -Dsut.jar="${IDENTITY_JAR}" \
  -Devomaster.instrumentation.jar.path="${EVOMASTER_AGENT}" \
  -Ddb.host="${DB_HOST}" \
  -Ddb.port="${DB_PORT}" \
  -Ddb.name="${DB_NAME}" \
  -Ddb.user="${DB_USER}" \
  -Ddb.password="${DB_PASS}" \
  -Dopenapi.url="https://raw.githubusercontent.com/OWASP/crAPI/main/openapi-spec/crapi-openapi-spec.json" \
  -jar "${DRIVER_JAR}" "${DRIVER_PORT}" \
  > "${OUTPUT_DIR}/driver.log" 2>&1 &
DRIVER_PID=$!

info "Driver PID: ${DRIVER_PID}  (logs: ${OUTPUT_DIR}/driver.log)"

# Wait until the driver TCP port is accepting connections.
# The /controller/api/infoSUT endpoint returns a non-2xx status before EvoMaster
# CLI has connected and started the SUT, so we check the port directly instead.
info "Waiting for EvoMaster driver to be ready…"
DRIVER_READY=false
for _ in $(seq 1 60); do
  if (echo >/dev/tcp/localhost/${DRIVER_PORT}) 2>/dev/null; then
    info "Driver is ready."
    DRIVER_READY=true
    break
  fi
  if ! kill -0 "${DRIVER_PID}" 2>/dev/null; then
    error "EvoMaster driver process died unexpectedly."
    error "Check ${OUTPUT_DIR}/driver.log for details."
    exit 1
  fi
  sleep 3
done

if [[ "${DRIVER_READY}" != "true" ]]; then
  error "EvoMaster driver did not become ready within 180 s."
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
  info "No seed collection found – running without --seedTestCases."
fi

info "Starting EvoMaster white-box test generation (budget: ${TIME_BUDGET})…"
java -jar "${EVOMASTER_CLI}" \
  --blackBox false \
  --problemType REST \
  --sutControllerHost localhost \
  --sutControllerPort "${DRIVER_PORT}" \
  --maxTime "${TIME_BUDGET}" \
  --outputFolder "${OUTPUT_DIR}" \
  --outputFormat JAVA_JUNIT_5 \
  --testSuiteName CrApiCommunityEvoMasterTest \
  --enableBasicAssertions true \
  --security true \
  --schemaOracles true \
  --expectationsActive true \
  --taintOnSampling true \
  --discoveredInfoRewardedInFitness true \
  --advancedBlackBoxCoverage true \
  --enableWriteSnapshotTests true \
  --writeStatistics true \
  --exportCoveredTarget true \
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
