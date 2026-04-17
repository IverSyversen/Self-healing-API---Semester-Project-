"""
OWASP ZAP scanner module.

Runs ZAP in daemon mode via Docker, spiders + active-scans the target,
then pulls the JSON report.

Requires Docker to be running.

Usage in config:
  zap_target:      "http://localhost:8888"
  zap_docker_image: "ghcr.io/zaproxy/zaproxy:stable"  # default
  zap_scan_timeout: 300  # seconds
"""

import json
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

DEFAULT_IMAGE   = "ghcr.io/zaproxy/zaproxy:stable"
DEFAULT_TIMEOUT = 300


def run(config: dict) -> List[dict]:
    target  = config.get("zap_target") or config.get("base_url")
    image   = config.get("zap_docker_image", DEFAULT_IMAGE)
    timeout = int(config.get("zap_scan_timeout", DEFAULT_TIMEOUT))

    if not target:
        log.warning("ZAP: no target URL configured — skipping")
        return []

    if not shutil.which("docker"):
        log.warning("Docker not found — skipping ZAP scan")
        return []

    report_dir = Path(__file__).parent.parent.parent / "reports"
    report_dir.mkdir(exist_ok=True)
    report_file = report_dir / "zap_report.json"

    # ZAP baseline (spider + passive) or full active scan
    cmd = [
        "docker", "run", "--rm",
        "--network", "host",                             # reach localhost services
        "-v", f"{report_dir}:/zap/wrk:rw",
        image,
        "zap-api-scan.py",
        "-t", target,
        "-f", "openapi",
        "-J", "zap_report.json",
        "-l", "PASS",
        "-T", str(timeout // 60),                       # ZAP uses minutes
    ]

    log.info("Running ZAP: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
        log.debug("ZAP stdout: %s", result.stdout[-1000:])
        if result.returncode not in (0, 2):              # 2 = warnings found
            log.warning("ZAP exited %d", result.returncode)
    except subprocess.TimeoutExpired:
        log.error("ZAP timed out")
        return []

    return _parse_report(report_file)


def _parse_report(report_file: Path) -> List[dict]:
    if not report_file.exists():
        log.warning("ZAP report not found: %s", report_file)
        return []

    with open(report_file) as f:
        data = json.load(f)

    alerts = []
    # ZAP JSON structure: { "site": [{ "alerts": [...] }] }
    for site in data.get("site", []):
        alerts += site.get("alerts", [])

    log.info("ZAP: %d alerts across all sites", len(alerts))
    return alerts   # normalizer.py handles the rest
