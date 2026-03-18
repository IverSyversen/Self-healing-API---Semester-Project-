"""
Remediation engine.

Maps a VulnerabilityReport to a RemediationPlan by loading the appropriate
JSON template and generating a human-readable patch description.

This is the *map* phase of the detect→map→fix lifecycle.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vulnerability_scanner.vulnerability_types import VulnerabilityReport, VulnerabilityType

# Canonical location of the bundled templates
_DEFAULT_TEMPLATES_DIR = Path(__file__).parent / "templates"

# Template file names keyed by vulnerability type
_TEMPLATE_FILES: Dict[VulnerabilityType, str] = {
    VulnerabilityType.SQL_INJECTION: "sql_injection.json",
    VulnerabilityType.BROKEN_AUTH: "broken_auth.json",
    VulnerabilityType.BROKEN_OBJECT_LEVEL_AUTH: "bola.json",
    VulnerabilityType.EXCESSIVE_DATA_EXPOSURE: "excessive_data_exposure.json",
    VulnerabilityType.MISSING_RATE_LIMITING: "missing_rate_limiting.json",
}


@dataclass
class RemediationPlan:
    """
    A remediation plan produced by the engine for a single vulnerability.

    Attributes:
        vulnerability:      The original VulnerabilityReport that triggered this plan.
        template:           The raw JSON template loaded from disk.
        fix_description:    Human-readable summary of what needs to change.
        patch_steps:        Ordered list of concrete actions to take.
        verification_rules: Rules that must pass after the patch is applied.
        references:         External links for further reading.
    """

    vulnerability: VulnerabilityReport
    template: dict
    fix_description: str
    patch_steps: List[str]
    verification_rules: List[str]
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "vulnerability": self.vulnerability.to_dict(),
            "fix_description": self.fix_description,
            "patch_steps": self.patch_steps,
            "verification_rules": self.verification_rules,
            "references": self.references,
            "code_pattern": self.template.get("code_pattern", {}),
        }

    def summary(self) -> str:
        lines = [
            f"[{self.vulnerability.severity.value}] {self.vulnerability.vulnerability_type.value}",
            f"  Location : {self.vulnerability.location}",
            f"  Endpoint : {self.vulnerability.endpoint}",
            f"  OWASP    : {self.vulnerability.owasp_category}",
            f"  Fix      : {self.fix_description}",
            "  Steps    :",
        ]
        for i, step in enumerate(self.patch_steps, 1):
            lines.append(f"    {i}. {step}")
        lines.append("  Verification :")
        for rule in self.verification_rules:
            lines.append(f"    ✓ {rule}")
        return "\n".join(lines)


class RemediationEngine:
    """
    Loads JSON remediation templates and produces RemediationPlan objects.

    The engine is intentionally template-driven so that the remediation logic
    is *not* hardcoded to any single microservice.  Adding support for a new
    vulnerability class requires only a new JSON file in the templates/ directory.
    """

    def __init__(self, templates_dir: Optional[str] = None) -> None:
        self._templates_dir = Path(templates_dir) if templates_dir else _DEFAULT_TEMPLATES_DIR
        self._cache: Dict[VulnerabilityType, dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_remediation_plan(self, vulnerability: VulnerabilityReport) -> Optional[RemediationPlan]:
        """
        Return a RemediationPlan for *vulnerability*, or ``None`` if no
        template exists for the detected vulnerability type.
        """
        template = self._load_template(vulnerability.vulnerability_type)
        if template is None:
            return None
        return RemediationPlan(
            vulnerability=vulnerability,
            template=template,
            fix_description=template.get("fix_description", "See references."),
            patch_steps=template.get("patch_steps", []),
            verification_rules=template.get("verification_rules", []),
            references=template.get("references", []),
        )

    def get_plans_for_all(
        self, vulnerabilities: List[VulnerabilityReport]
    ) -> List[RemediationPlan]:
        """Convenience wrapper: produce plans for every item in *vulnerabilities*."""
        plans: List[RemediationPlan] = []
        for vuln in vulnerabilities:
            plan = self.get_remediation_plan(vuln)
            if plan:
                plans.append(plan)
        return plans

    def list_supported_types(self) -> List[str]:
        """Return the vulnerability types for which templates are available."""
        return [vt.value for vt in _TEMPLATE_FILES if self._template_path(vt).exists()]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_template(self, vuln_type: VulnerabilityType) -> Optional[dict]:
        if vuln_type in self._cache:
            return self._cache[vuln_type]
        path = self._template_path(vuln_type)
        if not path.exists():
            return None
        with path.open(encoding="utf-8") as fh:
            template = json.load(fh)
        self._cache[vuln_type] = template
        return template

    def _template_path(self, vuln_type: VulnerabilityType) -> Path:
        filename = _TEMPLATE_FILES.get(vuln_type)
        if not filename:
            return self._templates_dir / "__nonexistent__.json"
        return self._templates_dir / filename
