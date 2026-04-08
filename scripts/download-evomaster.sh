#!/usr/bin/env bash
# =============================================================================
# download-evomaster.sh
#
# Downloads the EvoMaster CLI JAR and the Java bytecode-instrumentation agent
# from the official GitHub releases page.
#
# Artifacts are placed in /opt/evomaster/:
#   /opt/evomaster/evomaster.jar        – CLI used to run test generation
#   /opt/evomaster/evomaster-agent.jar  – Java agent for white-box instrumentation
# =============================================================================
set -euo pipefail

EVOMASTER_VERSION="3.3.0"
INSTALL_DIR="/opt/evomaster"
BASE_URL="https://github.com/EMResearch/EvoMaster/releases/download/v${EVOMASTER_VERSION}"

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

download_if_missing \
  "${BASE_URL}/evomaster-agent.jar" \
  "${INSTALL_DIR}/evomaster-agent.jar"

info "EvoMaster ${EVOMASTER_VERSION} artifacts ready in ${INSTALL_DIR}/"
info "  CLI:   ${INSTALL_DIR}/evomaster.jar"
info "  Agent: ${INSTALL_DIR}/evomaster-agent.jar"
