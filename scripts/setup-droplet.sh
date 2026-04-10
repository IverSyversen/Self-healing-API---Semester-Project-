#!/usr/bin/env bash
# =============================================================================
# setup-droplet.sh
#
# One-time setup for the DigitalOcean droplet.
# Run as root (or with sudo) on a fresh Ubuntu 22.04 droplet.
#
# What it does:
#   1. Installs Java 17 and Maven if they are not already present.
#   2. Calls download-evomaster.sh to fetch evomaster.jar and evomaster-agent.jar.
#   3. Calls build-community-jar.sh to fetch and build the crAPI identity service.
#   4. Builds the EvoMaster driver fat JAR.
#   5. Verifies that the crAPI Docker stack is (or can be) running.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    error "This script must be run as root or with sudo."
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# 1. Java 17
# ---------------------------------------------------------------------------
install_java() {
  if java -version 2>&1 | grep -q "version \"17"; then
    info "Java 17 already installed."
    return
  fi
  info "Installing Java 17 (OpenJDK)…"
  apt-get update -y
  apt-get install -y openjdk-17-jdk
  update-alternatives --set java "$(update-alternatives --list java | grep java-17)"
  info "Java version: $(java -version 2>&1 | head -1)"
}

# ---------------------------------------------------------------------------
# 2. Maven
# ---------------------------------------------------------------------------
install_maven() {
  if command -v mvn &>/dev/null; then
    info "Maven already installed: $(mvn -version 2>&1 | head -1)"
    return
  fi
  info "Installing Maven…"
  apt-get install -y maven
}

# ---------------------------------------------------------------------------
# 3. Docker (required for the crAPI stack)
# ---------------------------------------------------------------------------
install_docker() {
  if command -v docker &>/dev/null; then
    info "Docker already installed."
    return
  fi
  info "Installing Docker…"
  curl -fsSL https://get.docker.com | sh
}

# ---------------------------------------------------------------------------
# 4. Download EvoMaster artifacts
# ---------------------------------------------------------------------------
download_evomaster() {
  info "Downloading EvoMaster CLI and agent…"
  bash "${SCRIPT_DIR}/download-evomaster.sh"
}

# ---------------------------------------------------------------------------
# 5. Build the crAPI identity service JAR
# ---------------------------------------------------------------------------
build_identity_jar() {
  info "Building crAPI identity service JAR…"
  bash "${SCRIPT_DIR}/build-community-jar.sh"
}

# ---------------------------------------------------------------------------
# 6. Build the EvoMaster driver fat JAR
# ---------------------------------------------------------------------------
build_driver() {
  info "Building EvoMaster driver…"
  cd "${REPO_ROOT}/evomaster-driver"
  mvn package -q -DskipTests
  info "Driver JAR: ${REPO_ROOT}/evomaster-driver/target/crapi-community-driver-1.0.0.jar"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
require_root
install_java
install_maven
install_docker
download_evomaster
build_identity_jar
build_driver

info "===================================================================="
info "Setup complete.  Next step:"
info "  cd ${REPO_ROOT} && bash scripts/run-whitebox.sh"
info "===================================================================="
