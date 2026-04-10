#!/usr/bin/env bash
# =============================================================================
# build-community-jar.sh
#
# Fetches the crAPI identity service source from the OWASP GitHub repository,
# builds it with Gradle, and installs the resulting fat JAR at:
#
#   /opt/crapi/community-service.jar
#
# The EvoMaster driver (CrApiCommunityController) will spawn this JAR as an
# external process with the EvoMaster Java agent attached.
#
# NOTE: The crAPI community service (services/community) is written in Go and
# cannot be instrumented by EvoMaster's Java agent.  The identity service
# (services/identity, Java/Spring Boot) is used as the white-box target
# instead.
# =============================================================================
set -euo pipefail

CRAPI_REPO="https://github.com/OWASP/crAPI/archive/refs/heads/main.zip"
WORK_DIR="/tmp/crapi-build"
INSTALL_DIR="/opt/crapi"
JAR_TARGET="${INSTALL_DIR}/identity-service.jar"
JWKS_TARGET="${INSTALL_DIR}/jwks.json"

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; }

# ---------------------------------------------------------------------------
# Skip rebuild if JAR is already in place.
# ---------------------------------------------------------------------------
if [[ -f "${JAR_TARGET}" ]]; then
  info "Identity service JAR already present at ${JAR_TARGET} – skipping build."
  info "Delete the file and re-run this script to force a rebuild."
  exit 0
fi

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
for cmd in curl unzip java; do
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

# The crAPI community service (services/community) is Go – no JVM to instrument.
# Use the identity service (services/identity) as the white-box EvoMaster target.
IDENTITY_DIR="${WORK_DIR}/crAPI-main/services/identity"
if [[ ! -d "${IDENTITY_DIR}" ]]; then
  error "Identity service directory not found after extraction: ${IDENTITY_DIR}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Build with Gradle (the identity service uses Gradle, not Maven)
# ---------------------------------------------------------------------------
info "Building identity service JAR (this may take a few minutes)…"
chmod +x "${IDENTITY_DIR}/gradlew"
"${IDENTITY_DIR}/gradlew" -p "${IDENTITY_DIR}" bootJar -x test -q

# Locate the fat JAR produced by Spring Boot's bootJar task.
FAT_JAR=$(find "${IDENTITY_DIR}/build/libs" -maxdepth 1 \
  -name "*.jar" ! -name "*-plain.jar" ! -name "*-sources.jar" ! -name "*-javadoc.jar" \
  | sort | tail -1)

if [[ -z "${FAT_JAR}" ]]; then
  error "Gradle build succeeded but no JAR found under ${IDENTITY_DIR}/build/libs"
  exit 1
fi

info "Build successful: ${FAT_JAR}"

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
mkdir -p "${INSTALL_DIR}"
cp "${FAT_JAR}" "${JAR_TARGET}"
info "Identity service JAR installed at ${JAR_TARGET}"

# Install the JWKS file required by the identity service at runtime.
if [[ -f "${IDENTITY_DIR}/jwks.json" ]]; then
  cp "${IDENTITY_DIR}/jwks.json" "${JWKS_TARGET}"
  info "JWKS file installed at ${JWKS_TARGET}"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
rm -rf "${WORK_DIR}"
info "Build directory removed."
