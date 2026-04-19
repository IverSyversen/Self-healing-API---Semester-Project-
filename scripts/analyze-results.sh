#!/usr/bin/env bash
# Usage: bash scripts/analyze-results.sh [--stats <csv-file>] [--tests-dir <dir>]
# Defaults: --stats ./generated_tests/statistics.csv  --tests-dir ./generated_tests

set -euo pipefail

STATS_FILE="./generated_tests/statistics.csv"
TESTS_DIR="./generated_tests"
SECURITY_PHASE_MIN=60

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stats)    STATS_FILE="$2"; shift 2 ;;
    --tests-dir) TESTS_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ ! -f "$STATS_FILE" ]]; then
  echo "ERROR: stats file not found: $STATS_FILE" >&2
  exit 1
fi

# Parse CSV and emit all needed values in a single Python invocation
eval "$(python3 - "$STATS_FILE" "$SECURITY_PHASE_MIN" <<'PYEOF'
import csv, sys

SECURITY_PHASE_MIN = int(sys.argv[2])

with open(sys.argv[1]) as f:
    rows = list(csv.DictReader(f))

if not rows:
    print('echo "ERROR: empty CSV" >&2; exit 1')
    sys.exit(0)

row = rows[0]
g = lambda k: row.get(k, "").strip()

covered_targets  = g("coveredTargets")
num_branches     = g("numberOfBranches")
covered_2xx      = g("covered2xx")
errors_5xx       = g("errors5xx")
potential_faults = g("potentialFaults")
fault_summary    = g("potentialFaultsSummary")
elapsed          = g("elapsedSeconds")
phase_search     = g("phase_SEARCH")
phase_min        = g("phase_MINIMIZATION")
phase_sec        = g("phase_SECURITY")

try:
    branch_pct = f"{float(covered_targets)/float(num_branches)*100:.1f}" if float(num_branches) > 0 else "?"
except Exception:
    branch_pct = "?"

def fmt(s):
    try:
        s = int(s)
        m, r = divmod(s, 60)
        return f"{m}m {r}s" if m else f"{r}s"
    except Exception:
        return f"{s}s"

labels = {"100": "HTTP 500", "101": "Schema violations", "205": "Security oracle"}
fault_lines = []
if fault_summary:
    for pair in fault_summary.split("|"):
        if ":" in pair:
            code, count = pair.split(":", 1)
            label = labels.get(code, "Unknown")
            extra = "  <- BOLA/auth-bypass candidates" if code == "205" else ""
            fault_lines.append(f"  Cat {code} ({label}):{' '*(22-len(label))}{count}{extra}")
fault_output = "\n".join(fault_lines) if fault_lines else "  (none)"

try:
    sec_warn = int(phase_sec) < SECURITY_PHASE_MIN
except Exception:
    sec_warn = False

def q(s):
    return s.replace("'", "'\\''")

print(f"COVERED_TARGETS='{q(covered_targets)}'")
print(f"NUM_BRANCHES='{q(num_branches)}'")
print(f"COVERED_2XX='{q(covered_2xx)}'")
print(f"ERRORS_5XX='{q(errors_5xx)}'")
print(f"POTENTIAL_FAULTS='{q(potential_faults)}'")
print(f"ELAPSED_FMT='{q(fmt(elapsed))}'")
print(f"PHASE_SEARCH_FMT='{q(fmt(phase_search))}'")
print(f"PHASE_MIN_FMT='{q(fmt(phase_min))}'")
print(f"PHASE_SEC_FMT='{q(fmt(phase_sec))}'")
print(f"PHASE_SEC_RAW='{q(phase_sec)}'")
print(f"BRANCH_PCT='{q(branch_pct)}'")
print(f"FAULT_OUTPUT='{q(fault_output)}'")
print(f"SEC_WARN={'1' if sec_warn else '0'}")
PYEOF
)"

SEC_WARN_LABEL=""
if [[ "$SEC_WARN" -eq 1 ]]; then
  SEC_WARN_LABEL=" [WARN: < ${SECURITY_PHASE_MIN}s — security phase too short]"
fi

# BOLA endpoint search
BOLA_SECTION="  (tests-dir not found — skipping BOLA endpoint search)"
if [[ -d "$TESTS_DIR" ]]; then
  JAVA_FILES=("$TESTS_DIR"/*.java)
  if [[ -f "${JAVA_FILES[0]}" ]]; then
    BOLA_ENDPOINTS=$(grep -roh '"[^"]*vehicle[^"]*"' "${JAVA_FILES[@]}" 2>/dev/null \
      | grep -E "vehicleId|/vehicle/" \
      | sed 's/"//g; s/?.*$//' \
      | sort -u \
      | while read -r ep; do echo "  ✓  $ep"; done)
    BOLA_SECTION="${BOLA_ENDPOINTS:-(  (no vehicle/BOLA-related endpoints found in test files))}"
  else
    BOLA_SECTION="  (no .java test files found in $TESTS_DIR)"
  fi
fi

SEP="============================================================"

echo "$SEP"
echo " EvoMaster Security Run Summary"
echo "$SEP"
echo " Run time:         ${ELAPSED_FMT}"
echo " Search phase:     ${PHASE_SEARCH_FMT}"
echo " Minimization:     ${PHASE_MIN_FMT}"
echo " Security phase:   ${PHASE_SEC_FMT}${SEC_WARN_LABEL}"
echo ""
echo " Coverage:"
echo "   Covered targets:   ${COVERED_TARGETS} / ${NUM_BRANCHES} branches (${BRANCH_PCT}%)"
echo "   2xx responses:     ${COVERED_2XX}  (authenticated flows reached)"
echo "   5xx responses:     ${ERRORS_5XX}"
echo ""
echo " Faults Found:     ${POTENTIAL_FAULTS} total"
echo "$FAULT_OUTPUT"
echo ""
echo " BOLA Endpoints Touched:"
echo "$BOLA_SECTION"
echo ""
echo "$SEP"

if [[ "$SEC_WARN" -eq 1 ]]; then
  echo " [WARN] Security phase was only ${PHASE_SEC_FMT} — rerun with --extraPhaseBudgetPercentage 0.4"
  echo "$SEP"
  exit 1
fi
