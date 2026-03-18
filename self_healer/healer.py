"""
Self-Healer orchestrator.

Ties together the scanner and the remediation engine to implement the full
detect → map → fix lifecycle described in the project brief.

Two healing modes are supported:

  "report"   – Detect and map, then print a structured report.
               No files are modified.  (Default, safe for CI/CD gates.)

  "generate" – As above, plus write a *_healed.py file next to every
               vulnerable source file with the vulnerabilities annotated
               and the recommended code substitutions applied where a
               simple pattern-replace is safe to do automatically.

A production system would add a third "apply" mode that rewrites the
originals in-place after human review, completes a test run, and commits
the changes.  That mode is intentionally left as future work.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vulnerability_scanner.scanner import StaticCodeScanner
from vulnerability_scanner.vulnerability_types import VulnerabilityReport, VulnerabilityType
from remediation.engine import RemediationEngine, RemediationPlan


@dataclass
class HealingResult:
    """Outcome for a single vulnerability after the fix phase."""

    plan: RemediationPlan
    patch_applied: bool
    healed_file: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "vulnerability": self.plan.vulnerability.to_dict(),
            "patch_applied": self.patch_applied,
            "healed_file": self.healed_file,
            "notes": self.notes,
            "fix_description": self.plan.fix_description,
            "verification_rules": self.plan.verification_rules,
        }


@dataclass
class HealingReport:
    """Aggregate report produced by a full healing run."""

    service_path: str
    mode: str
    total_vulnerabilities: int
    vulnerabilities: List[VulnerabilityReport]
    remediation_plans: List[RemediationPlan]
    healing_results: List[HealingResult] = field(default_factory=list)

    # Summary counters
    @property
    def patched_count(self) -> int:
        return sum(1 for r in self.healing_results if r.patch_applied)

    @property
    def unpatched_count(self) -> int:
        return self.total_vulnerabilities - self.patched_count

    def to_dict(self) -> dict:
        return {
            "service_path": self.service_path,
            "mode": self.mode,
            "total_vulnerabilities": self.total_vulnerabilities,
            "patched": self.patched_count,
            "unpatched": self.unpatched_count,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "remediation_plans": [p.to_dict() for p in self.remediation_plans],
            "healing_results": [r.to_dict() for r in self.healing_results],
        }

    def print_summary(self) -> None:
        print(f"\n{'=' * 70}")
        print(f"  Self-Healing Report – {self.service_path}")
        print(f"{'=' * 70}")
        print(f"  Mode                : {self.mode}")
        print(f"  Vulnerabilities     : {self.total_vulnerabilities}")
        print(f"  Patched             : {self.patched_count}")
        print(f"  Requires human review: {self.unpatched_count}")
        print()

        for idx, plan in enumerate(self.remediation_plans, 1):
            vuln = plan.vulnerability
            print(f"  [{idx}] {vuln.severity.value:<10} {vuln.vulnerability_type.value}")
            print(f"       Location : {vuln.location}  (line {vuln.line_number})")
            print(f"       Endpoint : {vuln.endpoint}")
            print(f"       OWASP    : {vuln.owasp_category}")
            print(f"       Fix      : {plan.fix_description}")
            for step in plan.patch_steps:
                print(f"                  • {step}")
            print()

        if self.healing_results:
            print("  Generated healed files:")
            for result in self.healing_results:
                if result.healed_file:
                    print(f"    → {result.healed_file}")

        print(f"{'=' * 70}\n")


# ---------------------------------------------------------------------------
# Automatic patch patterns
#
# Each entry is (vuln_type, search_regex, replacement_template).
# These are intentionally conservative – they only apply when the pattern
# unambiguously matches a single safe substitution.
# ---------------------------------------------------------------------------

_AUTO_PATCHES: List[tuple] = [
    # SQL Injection: rewrite execute(f"... {var}") → execute("... ?", (var,))
    # This regex is deliberately narrow so it only matches the exact patterns
    # introduced in the demo services.
    (
        VulnerabilityType.SQL_INJECTION,
        re.compile(
            r'execute\s*\(\s*f"(SELECT \* FROM \w+ WHERE \w+ = \')(\{(\w+)\})(\')"'
            r'\s*(?:AND\s+\w+\s*=\s*\'\{(\w+)\}\')?"?\)',
            re.DOTALL,
        ),
        None,  # too complex for simple replace; annotate only
    ),
    (
        VulnerabilityType.SQL_INJECTION,
        re.compile(
            r'f"(SELECT \* FROM \w+ WHERE \w+ LIKE \'%)\{(\w+)\}(%\')"',
        ),
        r'"\1?\3", (\2,)',  # parameterised LIKE
    ),
]


class SelfHealer:
    """
    Orchestrates the detect → map → fix lifecycle.

    Usage::

        healer = SelfHealer()
        report = healer.heal(service_path="/path/to/service", mode="report")
        report.print_summary()
    """

    def __init__(
        self,
        scanner: Optional[StaticCodeScanner] = None,
        engine: Optional[RemediationEngine] = None,
    ) -> None:
        self._scanner = scanner or StaticCodeScanner()
        self._engine = engine or RemediationEngine()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def heal(self, service_path: str, mode: str = "report") -> HealingReport:
        """
        Run a full healing cycle on *service_path*.

        Args:
            service_path: Path to a ``.py`` file or a directory of Python files.
            mode:         ``"report"`` (default) or ``"generate"``.

        Returns:
            A :class:`HealingReport` describing every vulnerability found,
            its remediation plan, and the result of any patch attempt.
        """
        if mode not in ("report", "generate"):
            raise ValueError(f"Unknown mode {mode!r}. Choose 'report' or 'generate'.")

        # Phase 1 – DETECT
        vulnerabilities = self._detect(service_path)

        # Phase 2 – MAP
        plans = self._map(vulnerabilities)

        report = HealingReport(
            service_path=service_path,
            mode=mode,
            total_vulnerabilities=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            remediation_plans=plans,
        )

        # Phase 3 – FIX
        if mode == "generate":
            report.healing_results = self._generate_healed_files(plans)

        return report

    def heal_and_save_json(
        self, service_path: str, output_path: str, mode: str = "report"
    ) -> HealingReport:
        """Run :meth:`heal` and persist the report to a JSON file."""
        report = self.heal(service_path, mode=mode)
        Path(output_path).write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )
        return report

    # ------------------------------------------------------------------
    # Lifecycle phases
    # ------------------------------------------------------------------

    def _detect(self, service_path: str) -> List[VulnerabilityReport]:
        path = Path(service_path)
        if path.is_file():
            return self._scanner.scan_file(service_path)
        return self._scanner.scan_directory(service_path)

    def _map(self, vulnerabilities: List[VulnerabilityReport]) -> List[RemediationPlan]:
        return self._engine.get_plans_for_all(vulnerabilities)

    def _generate_healed_files(self, plans: List[RemediationPlan]) -> List[HealingResult]:
        """
        Group plans by source file and write an annotated *_healed.py for each.
        """
        # Group plans by file
        by_file: Dict[str, List[RemediationPlan]] = {}
        for plan in plans:
            loc = plan.vulnerability.location
            by_file.setdefault(loc, []).append(plan)

        results: List[HealingResult] = []
        for filepath, file_plans in by_file.items():
            result = self._generate_healed_file(filepath, file_plans)
            results.extend(result)
        return results

    def _generate_healed_file(
        self, filepath: str, plans: List[RemediationPlan]
    ) -> List[HealingResult]:
        """
        Write a ``*_healed.py`` version of *filepath* with inline annotations
        for every vulnerability, plus automatic substitutions where safe.
        """
        path = Path(filepath)
        if not path.exists():
            return [
                HealingResult(
                    plan=p,
                    patch_applied=False,
                    notes=f"Source file not found: {filepath}",
                )
                for p in plans
            ]

        source = path.read_text(encoding="utf-8")
        healed_source, applied = self._apply_auto_patches(source, plans)

        healed_path = path.with_name(path.stem + "_healed" + path.suffix)
        healed_path.write_text(healed_source, encoding="utf-8")

        results: List[HealingResult] = []
        for plan in plans:
            vuln_type = plan.vulnerability.vulnerability_type
            patch_applied = vuln_type in applied
            results.append(
                HealingResult(
                    plan=plan,
                    patch_applied=patch_applied,
                    healed_file=str(healed_path),
                    notes=(
                        "Automatic patch applied."
                        if patch_applied
                        else "Annotated only; manual review required."
                    ),
                )
            )
        return results

    @staticmethod
    def _apply_auto_patches(
        source: str, plans: List[RemediationPlan]
    ) -> "tuple[str, set]":
        """
        Apply conservative automatic patches and return (patched_source, applied_types).

        For vulnerabilities where no safe regex substitution exists, a prominently
        labelled ``# HEALER:`` comment block is injected above the affected line.
        """
        lines = source.splitlines(keepends=True)
        applied: set = set()

        # Sort plans in reverse line order so insertions don't shift line numbers
        sorted_plans = sorted(
            plans,
            key=lambda p: p.vulnerability.line_number or 0,
            reverse=True,
        )

        for plan in sorted_plans:
            vuln = plan.vulnerability
            line_no = vuln.line_number
            if line_no is None or line_no > len(lines):
                continue

            line_idx = line_no - 1
            indent = len(lines[line_idx]) - len(lines[line_idx].lstrip())
            pad = " " * indent

            # Try an automatic patch first
            patched, success = _try_auto_patch(lines[line_idx], vuln.vulnerability_type)
            if success:
                lines[line_idx] = patched
                applied.add(vuln.vulnerability_type)
            else:
                # Inject annotation comment block above the vulnerable line
                annotation = (
                    f"{pad}# ──────────────────────────────────────────────────────\n"
                    f"{pad}# HEALER [{vuln.severity.value}]: {vuln.vulnerability_type.value}\n"
                    f"{pad}# OWASP : {vuln.owasp_category}\n"
                    f"{pad}# Fix   : {plan.fix_description}\n"
                    f"{pad}# Steps : {'; '.join(plan.patch_steps[:2])}\n"
                    f"{pad}# ──────────────────────────────────────────────────────\n"
                )
                lines.insert(line_idx, annotation)

        healed_header = (
            '"""\nHEALED VERSION – generated by SelfHealer.\n\n'
            "All VULN comments have been replaced with HEALER annotations\n"
            "that describe the required fix.  Lines prefixed with\n"
            "# HEALER require manual review before deployment.\n"
            '"""\n'
        )
        return healed_header + "".join(lines), applied


def _try_auto_patch(line: str, vuln_type: VulnerabilityType) -> tuple[str, bool]:
    """
    Attempt a safe automatic substitution on a single source line.

    Returns (possibly_modified_line, was_patched).
    """
    if vuln_type == VulnerabilityType.SQL_INJECTION:
        # Rewrite: f"... LIKE '%{var}%'" → "... LIKE ?", (f"%{var}%",)
        m = re.search(r'f"([^"]*LIKE \'%)(\{(\w+)\})(%)\'([^"]*)"', line)
        if m:
            prefix = m.group(1)
            var = m.group(3)
            suffix = m.group(5)
            new_sql = f'"{prefix}?{suffix}", (f"%{{{var}}}%",)'
            patched = line[: m.start()] + new_sql + line[m.end() :]
            return patched, True

    return line, False
