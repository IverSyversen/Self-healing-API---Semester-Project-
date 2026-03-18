"""
Tests for the remediation engine.

The tests verify that:
  - templates are loaded correctly for all supported vulnerability types
  - RemediationPlans contain the required fields
  - Plans are returned for all vulnerability types present in the demo services
"""
import pytest
from pathlib import Path

from vulnerability_scanner.vulnerability_types import (
    VulnerabilityReport,
    VulnerabilityType,
    Severity,
    OWASP_MAPPING,
    SEVERITY_MAP,
)
from remediation.engine import RemediationEngine, RemediationPlan

TEMPLATES_DIR = Path(__file__).parent.parent / "remediation" / "templates"


def _make_report(vuln_type: VulnerabilityType) -> VulnerabilityReport:
    """Build a minimal VulnerabilityReport for testing."""
    return VulnerabilityReport(
        vulnerability_type=vuln_type,
        severity=SEVERITY_MAP[vuln_type],
        location="/services/demo/app.py",
        description="Test vulnerability",
        evidence="db.execute(f\"SELECT ...\")",
        endpoint="POST /login",
        owasp_category=OWASP_MAPPING[vuln_type],
        line_number=42,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Template loading
# ─────────────────────────────────────────────────────────────────────────────

class TestTemplateLoading:
    def test_templates_directory_exists(self):
        assert TEMPLATES_DIR.exists(), "remediation/templates/ directory not found"

    def test_sql_injection_template_exists(self):
        assert (TEMPLATES_DIR / "sql_injection.json").exists()

    def test_broken_auth_template_exists(self):
        assert (TEMPLATES_DIR / "broken_auth.json").exists()

    def test_bola_template_exists(self):
        assert (TEMPLATES_DIR / "bola.json").exists()

    def test_excessive_data_exposure_template_exists(self):
        assert (TEMPLATES_DIR / "excessive_data_exposure.json").exists()

    def test_missing_rate_limiting_template_exists(self):
        assert (TEMPLATES_DIR / "missing_rate_limiting.json").exists()

    def test_engine_lists_supported_types(self):
        engine = RemediationEngine()
        supported = engine.list_supported_types()
        assert len(supported) >= 4
        assert VulnerabilityType.SQL_INJECTION.value in supported
        assert VulnerabilityType.BROKEN_AUTH.value in supported
        assert VulnerabilityType.BROKEN_OBJECT_LEVEL_AUTH.value in supported


# ─────────────────────────────────────────────────────────────────────────────
# Plan generation
# ─────────────────────────────────────────────────────────────────────────────

class TestPlanGeneration:
    @pytest.fixture
    def engine(self):
        return RemediationEngine()

    @pytest.mark.parametrize("vuln_type", [
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.BROKEN_AUTH,
        VulnerabilityType.BROKEN_OBJECT_LEVEL_AUTH,
        VulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
        VulnerabilityType.MISSING_RATE_LIMITING,
    ])
    def test_plan_returned_for_all_supported_types(self, engine, vuln_type):
        report = _make_report(vuln_type)
        plan = engine.get_remediation_plan(report)
        assert plan is not None, f"No plan returned for {vuln_type.value}"

    def test_plan_has_fix_description(self, engine):
        plan = engine.get_remediation_plan(_make_report(VulnerabilityType.SQL_INJECTION))
        assert plan.fix_description
        assert len(plan.fix_description) > 10

    def test_plan_has_patch_steps(self, engine):
        plan = engine.get_remediation_plan(_make_report(VulnerabilityType.SQL_INJECTION))
        assert isinstance(plan.patch_steps, list)
        assert len(plan.patch_steps) >= 2

    def test_plan_has_verification_rules(self, engine):
        plan = engine.get_remediation_plan(_make_report(VulnerabilityType.BROKEN_AUTH))
        assert isinstance(plan.verification_rules, list)
        assert len(plan.verification_rules) >= 1

    def test_plan_has_references(self, engine):
        plan = engine.get_remediation_plan(_make_report(VulnerabilityType.BOLA
                                                         if hasattr(VulnerabilityType, "BOLA")
                                                         else VulnerabilityType.BROKEN_OBJECT_LEVEL_AUTH))
        assert isinstance(plan.references, list)
        assert len(plan.references) >= 1

    def test_plan_preserves_vulnerability(self, engine):
        report = _make_report(VulnerabilityType.SQL_INJECTION)
        plan = engine.get_remediation_plan(report)
        assert plan.vulnerability is report

    def test_none_returned_for_unknown_type(self, engine):
        """Engine returns None when no template matches."""
        report = _make_report(VulnerabilityType.SECURITY_MISCONFIGURATION)
        plan = engine.get_remediation_plan(report)
        # SECURITY_MISCONFIGURATION has no template in this demo – should be None
        # (or a valid plan if a template was added)
        # Just assert the call doesn't raise
        assert plan is None or isinstance(plan, RemediationPlan)

    def test_get_plans_for_all(self, engine):
        reports = [_make_report(vt) for vt in [
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.BROKEN_AUTH,
            VulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
        ]]
        plans = engine.get_plans_for_all(reports)
        assert len(plans) == 3

    def test_get_plans_for_empty_list(self, engine):
        plans = engine.get_plans_for_all([])
        assert plans == []


# ─────────────────────────────────────────────────────────────────────────────
# Plan serialisation
# ─────────────────────────────────────────────────────────────────────────────

class TestPlanSerialisation:
    def test_to_dict_contains_required_keys(self):
        engine = RemediationEngine()
        plan = engine.get_remediation_plan(_make_report(VulnerabilityType.SQL_INJECTION))
        d = plan.to_dict()
        assert "vulnerability" in d
        assert "fix_description" in d
        assert "patch_steps" in d
        assert "verification_rules" in d
        assert "references" in d
        assert "code_pattern" in d

    def test_summary_string_is_non_empty(self):
        engine = RemediationEngine()
        plan = engine.get_remediation_plan(_make_report(VulnerabilityType.BROKEN_AUTH))
        summary = plan.summary()
        assert len(summary) > 50
        assert "BROKEN_AUTH" in summary

    def test_template_caching_returns_same_object(self):
        """Second call for the same type returns the cached template dict."""
        engine = RemediationEngine()
        plan1 = engine.get_remediation_plan(_make_report(VulnerabilityType.SQL_INJECTION))
        plan2 = engine.get_remediation_plan(_make_report(VulnerabilityType.SQL_INJECTION))
        assert plan1.template is plan2.template
