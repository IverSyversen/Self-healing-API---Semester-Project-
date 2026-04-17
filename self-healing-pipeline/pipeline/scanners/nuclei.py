"""
Nuclei scanner module.

Runs nuclei against the target URL using the API security template pack,
then parses the JSONL output (one JSON object per line).

Install:
  brew install nuclei          # macOS
  nuclei -update-templates

Usage in config:
  nuclei_target:    "http://localhost:8888"
  nuclei_templates: ["api", "token"]   # sub-directories under ~/.nuclei-templates
  nuclei_extra_args: []
"""

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

NUCLEI_BIN = shutil.which("nuclei") or "nuclei"


def run(config: dict) -> List[dict]:
    target    = config.get("nuclei_target") or config.get("base_url")
    templates = config.get("nuclei_templates", ["api", "token", "http/misconfiguration"])
    extra     = config.get("nuclei_extra_args", [])

    if not target:
        log.warning("Nuclei: no target URL configured — skipping")
        return []

    if not shutil.which("nuclei"):
        log.warning("Nuclei binary not found — skipping (install with: brew install nuclei)")
        return []

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        out_file = tmp.name

    cmd = [
        NUCLEI_BIN,
        "-u", target,
        "-o", out_file,
        "-json",
        "-silent",
        "-severity", "info,low,medium,high,critical",
    ]
    for t in templates:
        cmd += ["-t", t]
    cmd += extra

    log.info("Running Nuclei: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode not in (0, 1):   # nuclei exits 1 when findings exist
            log.error("Nuclei exited %d: %s", result.returncode, result.stderr[:500])
    except subprocess.TimeoutExpired:
        log.error("Nuclei timed out after 300s")
        return []
    except FileNotFoundError:
        log.error("Nuclei binary not found")
        return []

    return _parse_output(out_file)


def _parse_output(out_file: str) -> List[dict]:
    path = Path(out_file)
    if not path.exists() or path.stat().st_size == 0:
        log.info("Nuclei: no findings")
        return []

    raw_findings = []
    with open(out_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw_findings.append(json.loads(line))
            except json.JSONDecodeError:
                log.debug("Nuclei: skipping non-JSON line: %s", line[:100])

    log.info("Nuclei: %d raw findings", len(raw_findings))
    return raw_findings   # normalizer.py handles the rest
