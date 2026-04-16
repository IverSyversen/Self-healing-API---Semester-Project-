#!/usr/bin/env bash
# =============================================================================
# download-evomaster.sh
#
# Downloads the EvoMaster CLI JAR from the official GitHub releases page and
# the Java bytecode-instrumentation agent from Maven Central.
#
# Artifacts are placed in ${INSTALL_DIR} (default /opt/evomaster):
#   ${INSTALL_DIR}/evomaster.jar        – CLI used to run test generation
#   ${INSTALL_DIR}/evomaster-agent.jar  – Java agent for white-box instrumentation
# =============================================================================
set -euo pipefail

EVOMASTER_VERSION="${EVOMASTER_VERSION:-5.1.0}"
INSTALL_DIR="${EVOMASTER_DIR:-/opt/evomaster}"
BASE_URL="https://github.com/WebFuzzing/EvoMaster/releases/download/v${EVOMASTER_VERSION}"
MAVEN_CENTRAL_URL="https://repo1.maven.org/maven2/org/evomaster"

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; }

mkdir -p "${INSTALL_DIR}"

# ---------------------------------------------------------------------------
# Download helper – skips the download if the file is already present.
# ---------------------------------------------------------------------------
download_if_missing() {
  local url="$1"
  local dest="$2"
  if [[ -f "${dest}" ]]; then
    info "Already present: ${dest}"
    return
  fi
  info "Downloading $(basename "${dest}") from ${url} …"
  curl -fsSL --retry 3 --retry-delay 5 -o "${dest}" "${url}"
  info "Saved to ${dest}"
}

download_if_missing \
  "${BASE_URL}/evomaster.jar" \
  "${INSTALL_DIR}/evomaster.jar"

# The Java bytecode-instrumentation agent is not a GitHub release asset;
# it is published to Maven Central as evomaster-client-java-instrumentation.
download_if_missing \
  "${MAVEN_CENTRAL_URL}/evomaster-client-java-instrumentation/${EVOMASTER_VERSION}/evomaster-client-java-instrumentation-${EVOMASTER_VERSION}.jar" \
  "${INSTALL_DIR}/evomaster-agent.jar"

info "EvoMaster ${EVOMASTER_VERSION} artifacts ready in ${INSTALL_DIR}/"
info "  CLI:   ${INSTALL_DIR}/evomaster.jar"
info "  Agent: ${INSTALL_DIR}/evomaster-agent.jar"
