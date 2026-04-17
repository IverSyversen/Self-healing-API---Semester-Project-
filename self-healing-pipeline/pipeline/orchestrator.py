"""
Self-healing API orchestrator.

Stages:
  1. SCAN    — run all configured scanners
  2. INGEST  — normalise + store findings in SQLite
  3. HEAL    — for each OPEN finding, apply the matching mitigation
  4. VERIFY  — re-scan to confirm each mitigation held
  5. REPORT  — print summary table

Usage:
  python -m pipeline.orchestrator                   # use pipeline/config.json
  python -m pipeline.orchestrator --config my.json  # custom config
  python -m pipeline.orchestrator --scan-only       # skip heal + verify
  python -m pipeline.orchestrator --heal-only       # skip scan, apply mitigations to OPEN findings
  python -m pipeline.orchestrator --verify-only     # skip scan + heal, just verify MITIGATED
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from pipeline import db
from pipeline.mitigations import registry
from pipeline import normalizer, verifier
from pipeline.scanners import evomaster, nuclei, zap, schemathesis

log = logging.getLogger(__name__)

DEFAULT_CONFIG = Path(__file__).parent.parent / "pipeline-config.json"


def main():
    parser = argparse.ArgumentParser(description="Self-healing API pipeline")
    parser.add_argument("--config",       default=str(DEFAULT_CONFIG))
    parser.add_argument("--scan-only",    action="store_true")
    parser.add_argument("--heal-only",    action="store_true")
    parser.add_argument("--verify-only",  action="store_true")
    parser.add_argument("--log-level",    default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    config = _load_config(args.config)
    db.init()
    registry.load()

    scanners_used = list(config.get("scanners", ["evomaster", "nuclei", "zap", "schemathesis"]))
    run_id = db.start_run(scanners_used)

    # ------------------------------------------------------------------
    # Stage 1 + 2: SCAN + INGEST
    # ------------------------------------------------------------------
    if not args.heal_only and not args.verify_only:
        _log_stage("SCAN")
        all_raw = _run_scanners(config, scanners_used)

        _log_stage("INGEST")
        new_count = 0
        for scanner_name, raw_findings in all_raw.items():
            for raw in raw_findings:
                normalised = normalizer.normalise(scanner_name, raw)
                if normalised is None:
                    continue
                fid = db.upsert_finding(normalised)
                new_count += 1

        open_findings = db.get_open_findings()
        log.info("Ingested %d findings | %d OPEN total", new_count, len(open_findings))

    # ------------------------------------------------------------------
    # Stage 3: HEAL
    # ------------------------------------------------------------------
    if not args.scan_only and not args.verify_only:
        _log_stage("HEAL")
        open_findings = db.get_open_findings()

        healed = 0
        skipped = 0
        for finding in open_findings:
            finding = dict(finding)
            mitigation = registry.lookup(finding["vuln_type"])

            if mitigation is None:
                log.warning("  No mitigation for vuln_type=%s — skipping", finding["vuln_type"])
                skipped += 1
                continue

            log.info(
                "  Healing [%s] %s %s → %s",
                finding["vuln_type"], finding["method"], finding["endpoint"],
                mitigation["id"]
            )
            ok = registry.apply(mitigation, config)
            if ok:
                db.mark_mitigated(finding["id"], mitigation["id"])
                healed += 1
            else:
                log.error("  Failed to apply %s", mitigation["id"])

        log.info("Healed %d findings | %d skipped (no mitigation)", healed, skipped)

    # ------------------------------------------------------------------
    # Stage 4: VERIFY
    # ------------------------------------------------------------------
    if not args.scan_only and not args.heal_only:
        _log_stage("VERIFY")
        results = verifier.verify_all(config)
        log.info(
            "Verification: %d passed ✅  |  %d failed ❌",
            len(results["passed"]), len(results["failed"])
        )

    # ------------------------------------------------------------------
    # Stage 5: REPORT
    # ------------------------------------------------------------------
    _log_stage("REPORT")
    db.finish_run(run_id)
    _print_summary()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_scanners(config: dict, scanners_used: list) -> dict:
    results = {}

    scanner_map = {
        "evomaster":   evomaster.run,
        "nuclei":      nuclei.run,
        "zap":         zap.run,
        "schemathesis": schemathesis.run,
    }

    for name in scanners_used:
        fn = scanner_map.get(name)
        if fn is None:
            log.warning("Unknown scanner: %s", name)
            continue
        log.info("  Running scanner: %s", name)
        try:
            results[name] = fn(config)
            log.info("  %s → %d raw findings", name, len(results[name]))
        except Exception as e:
            log.error("  Scanner %s failed: %s", name, e)
            results[name] = []

    return results


def _print_summary():
    findings = db.get_all_findings()
    counts = {"OPEN": 0, "MITIGATED": 0, "VERIFIED": 0, "FALSE_POSITIVE": 0}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1

    print()
    print("=" * 60)
    print("  SELF-HEALING PIPELINE — SUMMARY")
    print("=" * 60)
    print(f"  Total findings : {len(findings)}")
    print(f"  OPEN           : {counts['OPEN']}")
    print(f"  MITIGATED      : {counts['MITIGATED']}")
    print(f"  VERIFIED       : {counts['VERIFIED']}  ✅")
    print(f"  FALSE POSITIVE : {counts['FALSE_POSITIVE']}")
    print("=" * 60)

    if findings:
        print()
        print(f"  {'STATUS':<14} {'SCANNER':<12} {'VULN TYPE':<28} {'ENDPOINT'}")
        print(f"  {'-'*14} {'-'*12} {'-'*28} {'-'*30}")
        for f in findings:
            status_icon = {"VERIFIED": "✅", "MITIGATED": "🔧", "OPEN": "🔴", "FALSE_POSITIVE": "⬜"}.get(f["status"], "")
            print(
                f"  {status_icon} {f['status']:<12} {f['scanner']:<12} "
                f"{f['vuln_type']:<28} {f['method']} {f['endpoint']}"
            )
    print()


def _load_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        log.warning("Config file not found: %s — using defaults", config_path)
        return {}
    with open(path) as f:
        return json.load(f)


def _log_stage(name: str):
    log.info("")
    log.info("━━━━━━━━━━  %s  ━━━━━━━━━━", name)


if __name__ == "__main__":
    main()
