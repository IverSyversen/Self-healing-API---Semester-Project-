#!/usr/bin/env bash
# =============================================================================
# build-community-jar.sh
#
# Fetches the crAPI community service source from the OWASP GitHub repository,
# builds it with Maven, and installs the resulting fat JAR at:
#
#   /opt/crapi/community-service.jar
#
# The EvoMaster driver (CrApiCommunityController) will spawn this JAR as an
# external process with the EvoMaster Java agent attached.
# =============================================================================
set -euo pipefail

CRAPI_REPO="https://github.com/OWASP/crAPI/archive/refs/heads/main.zip"
WORK_DIR="/tmp/crapi-build"
INSTALL_DIR="/opt/crapi"
JAR_TARGET="${INSTALL_DIR}/community-service.jar"

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; }

# ---------------------------------------------------------------------------
# Skip rebuild if JAR is already in place.
# ---------------------------------------------------------------------------
if [[ -f "${JAR_TARGET}" ]]; then
  info "Community service JAR already present at ${JAR_TARGET} – skipping build."
  info "Delete the file and re-run this script to force a rebuild."
  exit 0
fi

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
for cmd in curl unzip mvn java; do
  if ! command -v "${cmd}" &>/dev/null; then
    error "Required command not found: ${cmd}"
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Download crAPI source
# ---------------------------------------------------------------------------
info "Downloading crAPI source archive…"
mkdir -p "${WORK_DIR}"
curl -fsSL --retry 3 --retry-delay 5 \
  -o "${WORK_DIR}/crapi-main.zip" \
  "${CRAPI_REPO}"

info "Extracting archive…"
unzip -q -o "${WORK_DIR}/crapi-main.zip" -d "${WORK_DIR}"

COMMUNITY_DIR="${WORK_DIR}/crAPI-main/services/community"
if [[ ! -d "${COMMUNITY_DIR}" ]]; then
  error "Community service directory not found after extraction: ${COMMUNITY_DIR}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Build with Maven
# ---------------------------------------------------------------------------
info "Building community service JAR (this may take a few minutes)…"
cd "${COMMUNITY_DIR}"
mvn package -q -DskipTests \
  -Dmaven.test.skip=true \
  -Dmaven.javadoc.skip=true

# Locate the fat JAR (Spring Boot repackages it).
FAT_JAR=$(find "${COMMUNITY_DIR}/target" -maxdepth 1 \
  -name "*.jar" ! -name "*-sources.jar" ! -name "*-javadoc.jar" \
  | sort | tail -1)

if [[ -z "${FAT_JAR}" ]]; then
  error "Maven build succeeded but no JAR found under ${COMMUNITY_DIR}/target"
  exit 1
fi

info "Build successful: ${FAT_JAR}"

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
mkdir -p "${INSTALL_DIR}"
cp "${FAT_JAR}" "${JAR_TARGET}"
info "Community service JAR installed at ${JAR_TARGET}"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
rm -rf "${WORK_DIR}"
info "Build directory removed."
