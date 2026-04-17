"""
EvoMaster scanner module.

Reads results from a completed EvoMaster run rather than executing EvoMaster
itself (EvoMaster is long-running and managed by run-whitebox.sh).

Two sources of findings:
  1. statistics.csv  — aggregate fault counts + categories
  2. generated Java test files — extract individual fault details
"""

import csv
import logging
import re
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

# Default locations — override via config
# scanners/ -> pipeline/ -> self-healing-pipeline/ -> project root
DEFAULT_STATS_FILE   = Path(__file__).parent.parent.parent.parent / "statistics.csv"
DEFAULT_TESTS_DIR    = Path(__file__).parent.parent.parent.parent / "generated_tests"


def run(config: dict) -> List[dict]:
    stats_file = Path(config.get("evomaster_stats", DEFAULT_STATS_FILE))
    tests_dir  = Path(config.get("evomaster_tests_dir", DEFAULT_TESTS_DIR))

    findings = []
    findings += _parse_statistics(stats_file)
    findings += _parse_generated_tests(tests_dir)
    return findings


# ---------------------------------------------------------------------------
# statistics.csv
# ---------------------------------------------------------------------------

def _parse_statistics(stats_file: Path) -> List[dict]:
    if not stats_file.exists():
        log.warning("EvoMaster statistics.csv not found: %s", stats_file)
        return []

    with open(stats_file) as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        return []

    # Use the most recent row (appendToStatisticsFile may have multiple)
    row = rows[-1]
    findings = []

    # --- 5xx errors ---------------------------------------------------------
    try:
        errors5xx = int(row.get("errors5xx", 0) or 0)
    except ValueError:
        errors5xx = 0

    if errors5xx > 0:
        findings.append({
            "scanner":   "evomaster",
            "vuln_type": "SERVER_ERROR_500",
            "endpoint":  "",   # detailed endpoints come from test files
            "method":    "",
            "severity":  "HIGH",
            "evidence":  f"EvoMaster found {errors5xx} HTTP 5xx responses",
        })

    # --- Potential fault categories -----------------------------------------
    # potentialFaultSummary format: "100:17|101:26|205:15"
    #   100 = 500 errors, 101 = assertion failures, 205 = schema violations
    summary = row.get("potentialFaultsSummary", "") or ""
    category_map = {
        "100": ("SERVER_ERROR_500",     "HIGH"),
        "101": ("SCHEMA_VIOLATION",     "MEDIUM"),
        "205": ("SCHEMA_VIOLATION",     "MEDIUM"),
    }
    for part in summary.split("|"):
        if ":" not in part:
            continue
        code, count_str = part.split(":", 1)
        try:
            count = int(count_str)
        except ValueError:
            continue
        if count == 0 or code not in category_map:
            continue
        vuln_type, severity = category_map[code]
        findings.append({
            "scanner":   "evomaster",
            "vuln_type": vuln_type,
            "endpoint":  "",
            "method":    "",
            "severity":  severity,
            "evidence":  f"EvoMaster fault category {code}: {count} instances",
        })

    log.info("EvoMaster stats: %d aggregate findings", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Generated Java test files
# ---------------------------------------------------------------------------

# Patterns to extract per-test fault info
_STATUS_RE  = re.compile(r'res\d*\.getStatusCode\(\).*?(\d{3})', re.DOTALL)
_PATH_RE    = re.compile(r'"(\/[^"]+)"')
_METHOD_RE  = re.compile(r'\.(get|post|put|delete|patch|options|head)\(', re.IGNORECASE)
_ASSERT_RE  = re.compile(r'assert.*?5\d\d', re.IGNORECASE)

FAULT_TEST_MARKER = re.compile(
    r'(test.*?fault|@Test.*?\n.*?5\d\d|oracles.*?5\d\d)',
    re.IGNORECASE | re.DOTALL
)


def _parse_generated_tests(tests_dir: Path) -> List[dict]:
    if not tests_dir.exists():
        return []

    findings = []
    seen = set()

    for java_file in tests_dir.glob("**/*.java"):
        text = java_file.read_text(errors="replace")
        findings += _extract_faults_from_test(java_file.name, text, seen)

    log.info("EvoMaster test files: %d distinct fault findings", len(findings))
    return findings


def _extract_faults_from_test(filename: str, text: str, seen: set) -> List[dict]:
    findings = []

    # Split by @Test methods
    test_methods = re.split(r'@Test\b', text)

    for method_body in test_methods[1:]:   # skip everything before first @Test
        # Only care about methods that reference 5xx status codes
        if not re.search(r'\b5\d\d\b', method_body):
            continue

        # Extract path
        paths = _PATH_RE.findall(method_body)
        endpoint = next((p for p in paths if p.startswith("/identity")), "")

        # Extract HTTP method
        method_match = _METHOD_RE.search(method_body)
        http_method = method_match.group(1).upper() if method_match else ""

        # Extract status code
        status_match = re.search(r'\b(5\d\d)\b', method_body)
        status_code = status_match.group(1) if status_match else "5xx"

        key = (endpoint, http_method, status_code)
        if key in seen:
            continue
        seen.add(key)

        # Build a short evidence snippet
        snippet_lines = []
        for line in method_body.splitlines()[:40]:
            stripped = line.strip()
            if stripped and not stripped.startswith("//"):
                snippet_lines.append(stripped)
            if len(snippet_lines) >= 5:
                break
        evidence = f"HTTP {status_code} on {http_method} {endpoint} | {' '.join(snippet_lines[:2])}"

        findings.append({
            "scanner":   "evomaster",
            "vuln_type": "SERVER_ERROR_500",
            "endpoint":  endpoint,
            "method":    http_method,
            "severity":  "HIGH",
            "evidence":  evidence[:500],
        })

    return findings
