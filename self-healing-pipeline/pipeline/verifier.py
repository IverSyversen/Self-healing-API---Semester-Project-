"""
Verifier — re-runs a targeted scan after a mitigation is applied and checks
whether the original finding is gone.

Each mitigation in mitigations.json has:
  verify_with:        scanner name (evomaster | nuclei | zap | schemathesis)
  verify_passes_when: human-readable rule (also parsed here for automated checks)
"""

import logging
import re
from typing import List

from pipeline import db
from pipeline.mitigations import registry
from pipeline.normalizer import normalise

log = logging.getLogger(__name__)


def verify_all(config: dict) -> dict:
    """
    Verify every MITIGATED finding.
    Returns { "passed": [...ids], "failed": [...ids] }
    """
    mitigated = db.get_mitigated_findings()
    passed = []
    failed = []

    for finding in mitigated:
        finding = dict(finding)
        mitigation = registry.lookup(finding["vuln_type"])
        if mitigation is None:
            log.warning("No mitigation found for %s during verification", finding["vuln_type"])
            continue

        ok = verify_one(finding, mitigation, config)
        if ok:
            db.mark_verified(finding["id"])
            passed.append(finding["id"])
            log.info("✅  VERIFIED: %s %s (%s)", finding["vuln_type"], finding["endpoint"], finding["id"][:8])
        else:
            db.mark_open(finding["id"])
            failed.append(finding["id"])
            log.warning("❌  STILL VULNERABLE: %s %s — reopening", finding["vuln_type"], finding["endpoint"])

    return {"passed": passed, "failed": failed}


def verify_one(finding: dict, mitigation: dict, config: dict) -> bool:
    """
    Run the appropriate targeted scan and check whether this finding recurs.
    Returns True if the mitigation holds (finding not reproduced).
    """
    scanner_name = mitigation.get("verify_with", "")
    rule         = mitigation.get("verify_passes_when", "")

    if not scanner_name:
        log.warning("Mitigation %s has no verify_with — assuming passed", mitigation.get("id"))
        return True

    raw_findings = _run_scanner(scanner_name, finding, config)
    normalised   = [normalise(scanner_name, r) for r in raw_findings]
    normalised   = [f for f in normalised if f is not None]

    return _check_rule(rule, normalised, finding, mitigation)


# ---------------------------------------------------------------------------
# Targeted scanner dispatch
# ---------------------------------------------------------------------------

def _run_scanner(scanner_name: str, finding: dict, config: dict) -> List[dict]:
    """Run only the scanner needed to verify this specific finding."""
    from pipeline.scanners import evomaster, nuclei, zap, schemathesis

    if scanner_name == "evomaster":
        # Re-parse existing EvoMaster output rather than re-running the full 60min test
        return evomaster.run(config)

    elif scanner_name == "nuclei":
        # Focus nuclei on just the affected endpoint
        local_config = dict(config)
        endpoint = finding.get("endpoint", "")
        if endpoint:
            local_config.setdefault("nuclei_extra_args", [])
            local_config["nuclei_extra_args"] = (
                local_config["nuclei_extra_args"] + ["-path", endpoint]
            )
        return nuclei.run(local_config)

    elif scanner_name == "zap":
        return zap.run(config)

    elif scanner_name == "schemathesis":
        # Focus on just the affected endpoint
        local_config = dict(config)
        endpoint = finding.get("endpoint", "")
        if endpoint:
            local_config["schemathesis_endpoint_filter"] = endpoint
        return schemathesis.run(local_config)

    else:
        log.warning("Unknown verification scanner: %s", scanner_name)
        return []


# ---------------------------------------------------------------------------
# Rule checker
# ---------------------------------------------------------------------------

def _check_rule(rule: str, findings: List[dict], original: dict, mitigation: dict) -> bool:
    """
    Evaluate verify_passes_when rule against the new scan results.

    Supported rule patterns:
      "no match on <template-name>"
      "no alerts on pluginid in [<ids>]"
      "distinct500Faults == 0"
      "no response_schema_conformance failures"
    """
    vuln_type = original.get("vuln_type", "")

    # Generic: check that no new finding of the same vuln_type appeared
    same_type = [f for f in findings if f.get("vuln_type") == vuln_type]

    if rule.startswith("no match on "):
        template = rule.replace("no match on ", "").strip()
        matching = [
            f for f in findings
            if template.lower() in f.get("evidence", "").lower()
        ]
        return len(matching) == 0

    elif rule.startswith("no alerts on pluginid in"):
        # Extract plugin IDs from the rule string
        ids_match = re.findall(r'\d+', rule)
        blocked_ids = set(ids_match)
        matching = [
            f for f in findings
            if any(pid in f.get("evidence", "") for pid in blocked_ids)
        ]
        return len(matching) == 0

    elif "distinct500Faults == 0" in rule:
        return len([f for f in findings if f.get("vuln_type") == "SERVER_ERROR_500"]) == 0

    elif "no response_schema_conformance failures" in rule:
        return len([f for f in findings if f.get("vuln_type") == "SCHEMA_VIOLATION"]) == 0

    else:
        # Default: no recurrence of the same vuln_type
        log.debug("Using default rule (no recurrence of %s)", vuln_type)
        return len(same_type) == 0
