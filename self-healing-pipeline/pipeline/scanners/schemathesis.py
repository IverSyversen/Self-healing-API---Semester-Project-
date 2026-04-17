"""
Schemathesis scanner module.

Runs schemathesis against an OpenAPI spec URL or file, collecting
crashes and schema violations across all services.

Install:  pip install schemathesis

Usage in config:
  schemathesis_schema:  "http://localhost:8888/openapi.json"
  schemathesis_target:  "http://localhost:8888"
  schemathesis_checks:  ["not_a_server_error", "response_schema_conformance"]
  schemathesis_workers: 4
  schemathesis_max_examples: 50
"""

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)


def run(config: dict) -> List[dict]:
    schema  = config.get("schemathesis_schema")
    target  = config.get("schemathesis_target") or config.get("base_url")
    checks  = config.get("schemathesis_checks",
                         ["not_a_server_error", "response_schema_conformance"])
    workers = config.get("schemathesis_workers", 2)
    max_ex  = config.get("schemathesis_max_examples", 30)

    if not schema:
        log.warning("Schemathesis: no schema URL/path configured — skipping")
        return []

    if not shutil.which("schemathesis"):
        log.warning("schemathesis not found — skipping (pip install schemathesis)")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        out_file = tmp.name

    cmd = [
        "schemathesis", "run",
        schema,
        "--report", out_file,
        "--report-format", "json",
        "--workers", str(workers),
        "--max-examples", str(max_ex),
        "--hypothesis-suppress-health-check=too_slow",
    ]

    if target and target not in schema:
        cmd += ["--base-url", target]

    for check in checks:
        cmd += ["--checks", check]

    # Pass auth headers if configured
    auth_header = config.get("schemathesis_auth_header")
    if auth_header:
        cmd += ["--header", auth_header]

    log.info("Running Schemathesis: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode not in (0, 1):
            log.warning("Schemathesis exited %d: %s", result.returncode, result.stderr[:500])
    except subprocess.TimeoutExpired:
        log.error("Schemathesis timed out")
        return []
    except FileNotFoundError:
        log.error("schemathesis binary not found")
        return []

    return _parse_output(out_file)


def _parse_output(out_file: str) -> List[dict]:
    path = Path(out_file)
    if not path.exists() or path.stat().st_size == 0:
        log.info("Schemathesis: no findings")
        return []

    try:
        with open(out_file) as f:
            data = json.load(f)
    except json.JSONDecodeError:
        log.error("Schemathesis: could not parse output JSON")
        return []

    raw_findings = []

    # Schemathesis JSON report structure:
    # { "results": { "/path": { "GET": { "errors": [...], "failures": [...] } } } }
    results = data.get("results", {})
    for path, methods in results.items():
        for method, detail in methods.items():
            for category in ("errors", "failures"):
                for item in detail.get(category, []):
                    raw_findings.append({
                        "path":        path,
                        "method":      method,
                        "status_code": item.get("response", {}).get("status_code", 500),
                        "checks":      item.get("checks", []),
                        "category":    category,
                    })

    log.info("Schemathesis: %d raw findings", len(raw_findings))
    return raw_findings
