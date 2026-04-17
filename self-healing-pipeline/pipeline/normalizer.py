"""
Maps raw scanner output to the common Finding schema.

Each scanner module returns a list of dicts with tool-specific keys.
This module normalises them into a consistent shape before DB storage.

Common vuln_type values (add more as needed):
  SERVER_ERROR_500
  SCHEMA_VIOLATION
  MISSING_SECURITY_HEADERS
  JWT_ALG_NONE
  JWT_CONFUSION
  BOLA_OBJECT_ACCESS
  RATE_LIMIT_MISSING
  MASS_ASSIGNMENT
  SQL_INJECTION
  EXCESSIVE_DATA_EXPOSURE
  BFLA_UNAUTHORISED_ACCESS
  UNKNOWN
"""

from datetime import datetime, timezone
from typing import Optional


# Severity bands
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "informational": "INFO",
}

# Map Nuclei template IDs → our vuln_type
NUCLEI_TEMPLATE_MAP = {
    "jwt-algorithm-confusion":          "JWT_CONFUSION",
    "jwt-none-algorithm":               "JWT_ALG_NONE",
    "jwt-alg-none":                     "JWT_ALG_NONE",
    "rate-limit-bypass":                "RATE_LIMIT_MISSING",
    "bola":                             "BOLA_OBJECT_ACCESS",
    "idor":                             "BOLA_OBJECT_ACCESS",
    "mass-assignment":                  "MASS_ASSIGNMENT",
    "sql-injection":                    "SQL_INJECTION",
    "sqli":                             "SQL_INJECTION",
    "excessive-data-exposure":          "EXCESSIVE_DATA_EXPOSURE",
    "broken-function-level-auth":       "BFLA_UNAUTHORISED_ACCESS",
}

# Map ZAP alert IDs → our vuln_type
ZAP_ALERT_MAP = {
    10021: "MISSING_SECURITY_HEADERS",   # X-Content-Type-Options
    10036: "MISSING_SECURITY_HEADERS",   # Server leaks info
    10037: "MISSING_SECURITY_HEADERS",   # Server leaks info via "X-Powered-By"
    10038: "MISSING_SECURITY_HEADERS",   # Content Security Policy
    10096: "MISSING_SECURITY_HEADERS",   # Timestamp disclosure
    90033: "MISSING_SECURITY_HEADERS",   # Loosely Scoped Cookie
    40014: "SQL_INJECTION",
    40018: "SQL_INJECTION",
    40024: "SQL_INJECTION",
    90020: "SQL_INJECTION",
    10010: "MISSING_SECURITY_HEADERS",   # Cookie No HttpOnly
    10016: "MISSING_SECURITY_HEADERS",   # Web Browser XSS Protection
    10017: "MISSING_SECURITY_HEADERS",   # Cross-Domain JavaScript Source File Inclusion
    10020: "MISSING_SECURITY_HEADERS",   # X-Frame-Options
}


def normalise(scanner: str, raw: dict) -> Optional[dict]:
    """
    Convert a raw scanner finding dict to the common finding schema.
    Returns None if the finding should be skipped.
    """
    if scanner == "evomaster":
        return _from_evomaster(raw)
    elif scanner == "nuclei":
        return _from_nuclei(raw)
    elif scanner == "zap":
        return _from_zap(raw)
    elif scanner == "schemathesis":
        return _from_schemathesis(raw)
    else:
        return _generic(scanner, raw)


# ---------------------------------------------------------------------------
# Per-scanner normalisers
# ---------------------------------------------------------------------------

def _from_evomaster(raw: dict) -> Optional[dict]:
    """
    EvoMaster findings come from two sources:
      1. statistics.csv rows (aggregate counts)
      2. Individual fault entries extracted from the generated test files
    The scanner module emits one dict per distinct fault.
    """
    vuln_type = raw.get("vuln_type", "UNKNOWN")
    return {
        "scanner":   "evomaster",
        "vuln_type": vuln_type,
        "endpoint":  raw.get("endpoint", ""),
        "method":    raw.get("method", ""),
        "severity":  raw.get("severity", "MEDIUM"),
        "evidence":  raw.get("evidence", ""),
        "timestamp": raw.get("timestamp", _now()),
    }


def _from_nuclei(raw: dict) -> Optional[dict]:
    """
    Nuclei outputs one JSON object per line.
    Key fields: template-id, info.severity, matched-at, matcher-name
    """
    template_id = raw.get("template-id", "")
    vuln_type = NUCLEI_TEMPLATE_MAP.get(template_id.lower(), "UNKNOWN")

    if vuln_type == "UNKNOWN":
        # Try fuzzy match on template tags
        tags = raw.get("info", {}).get("tags", "")
        for key, vt in NUCLEI_TEMPLATE_MAP.items():
            if key in tags.lower():
                vuln_type = vt
                break

    matched_at = raw.get("matched-at", "")
    # matched-at is typically the full URL — extract path
    endpoint = ""
    method = ""
    if matched_at:
        from urllib.parse import urlparse
        parsed = urlparse(matched_at)
        endpoint = parsed.path
    if raw.get("request"):
        method = raw["request"].split(" ")[0]

    severity = SEVERITY_MAP.get(
        raw.get("info", {}).get("severity", "").lower(), "MEDIUM"
    )

    return {
        "scanner":   "nuclei",
        "vuln_type": vuln_type,
        "endpoint":  endpoint,
        "method":    method,
        "severity":  severity,
        "evidence":  (
            f"Template: {template_id} | "
            f"Matcher: {raw.get('matcher-name','')} | "
            f"Matched: {matched_at}"
        ),
        "timestamp": raw.get("timestamp", _now()),
    }


def _from_zap(raw: dict) -> Optional[dict]:
    """
    ZAP alert JSON structure:
    {
      "pluginid": "10021",
      "alertRef": "...",
      "alert": "X-Content-Type-Options Header Missing",
      "name": "...",
      "riskcode": "1",   # 0=Info,1=Low,2=Medium,3=High
      "confidence": "2",
      "riskdesc": "Low (Medium)",
      "desc": "...",
      "instances": [{ "uri": "...", "method": "...", "evidence": "..." }]
    }
    """
    plugin_id = int(raw.get("pluginid", 0))
    vuln_type = ZAP_ALERT_MAP.get(plugin_id, "UNKNOWN")

    riskcode = int(raw.get("riskcode", 1))
    severity_map = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}
    severity = severity_map.get(riskcode, "MEDIUM")

    instances = raw.get("instances", [{}])
    first = instances[0] if instances else {}
    from urllib.parse import urlparse
    uri = first.get("uri", "")
    endpoint = urlparse(uri).path if uri else ""
    method = first.get("method", "")

    return {
        "scanner":   "zap",
        "vuln_type": vuln_type,
        "endpoint":  endpoint,
        "method":    method,
        "severity":  severity,
        "evidence":  (
            f"Alert: {raw.get('alert','')} | "
            f"Desc: {raw.get('desc','')[:200]}"
        ),
        "timestamp": _now(),
    }


def _from_schemathesis(raw: dict) -> Optional[dict]:
    """
    Schemathesis --output-file (JSON) format.
    Each failure is a dict with: method, path, status_code, response, checks
    """
    status_code = raw.get("status_code", 0)

    if status_code >= 500:
        vuln_type = "SERVER_ERROR_500"
        severity = "HIGH"
    else:
        vuln_type = "SCHEMA_VIOLATION"
        severity = "MEDIUM"

    checks = raw.get("checks", [])
    failed = [c for c in checks if not c.get("passed", True)]
    evidence_parts = [f"{c.get('name','')}: {c.get('message','')}" for c in failed]

    return {
        "scanner":   "schemathesis",
        "vuln_type": vuln_type,
        "endpoint":  raw.get("path", ""),
        "method":    raw.get("method", "").upper(),
        "severity":  severity,
        "evidence":  " | ".join(evidence_parts) or f"HTTP {status_code}",
        "timestamp": _now(),
    }


def _generic(scanner: str, raw: dict) -> dict:
    return {
        "scanner":   scanner,
        "vuln_type": raw.get("vuln_type", "UNKNOWN"),
        "endpoint":  raw.get("endpoint", ""),
        "method":    raw.get("method", ""),
        "severity":  raw.get("severity", "MEDIUM"),
        "evidence":  raw.get("evidence", str(raw)),
        "timestamp": raw.get("timestamp", _now()),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
