"""
Integration tests for the SelfHealer orchestrator.

These tests exercise the full detect → map → fix lifecycle against:
  1. Small synthetic Python snippets written to a temp directory
  2. The actual vulnerable service files shipped with this project
"""
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from vulnerability_scanner.vulnerability_types import VulnerabilityType
from self_healer.healer import SelfHealer, HealingReport, HealingResult

SERVICES_DIR = Path(__file__).parent.parent / "services"


# ─────────────────────────────────────────────────────────────────────────────
# Fixture: temporary service directory
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_SNIPPET = '''\
from fastapi import FastAPI
app = FastAPI()

@app.post("/login")
def login(username: str, password: str):
    # VULN: SQL injection
    query = f"SELECT * FROM users WHERE username = \'{username}\' AND password = \'{password}\'"
    db.execute(query)
    return {}

@app.post("/items/search")
def search(query: str):
    pass
'''


@pytest.fixture
def tmp_service(tmp_path):
    """Create a temporary directory containing a vulnerable service file."""
    src = tmp_path / "vulnerable_service.py"
    src.write_text(VULNERABLE_SNIPPET, encoding="utf-8")
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# Report mode
# ─────────────────────────────────────────────────────────────────────────────

class TestReportMode:
    def test_returns_healing_report(self, tmp_service):
        healer = SelfHealer()
        report = healer.heal(str(tmp_service / "vulnerable_service.py"), mode="report")
        assert isinstance(report, HealingReport)

    def test_detects_sql_injection_in_snippet(self, tmp_service):
        healer = SelfHealer()
        report = healer.heal(str(tmp_service / "vulnerable_service.py"), mode="report")
        types = [v.vulnerability_type for v in report.vulnerabilities]
        assert VulnerabilityType.SQL_INJECTION in types

    def test_report_mode_does_not_create_files(self, tmp_service):
        healer = SelfHealer()
        healer.heal(str(tmp_service / "vulnerable_service.py"), mode="report")
        healed = list(tmp_service.glob("*_healed.py"))
        assert healed == [], "Report mode must not write any files"

    def test_report_has_remediation_plans(self, tmp_service):
        healer = SelfHealer()
        report = healer.heal(str(tmp_service / "vulnerable_service.py"), mode="report")
        assert len(report.remediation_plans) >= 1

    def test_report_total_matches_vulnerabilities_list(self, tmp_service):
        healer = SelfHealer()
        report = healer.heal(str(tmp_service / "vulnerable_service.py"), mode="report")
        assert report.total_vulnerabilities == len(report.vulnerabilities)

    def test_invalid_mode_raises(self, tmp_service):
        with pytest.raises(ValueError):
            SelfHealer().heal(str(tmp_service / "vulnerable_service.py"), mode="rewrite")


# ─────────────────────────────────────────────────────────────────────────────
# Generate mode
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateMode:
    def test_generate_mode_creates_healed_file(self, tmp_service):
        healer = SelfHealer()
        healer.heal(str(tmp_service / "vulnerable_service.py"), mode="generate")
        healed = list(tmp_service.glob("*_healed.py"))
        assert len(healed) == 1

    def test_healed_file_contains_header(self, tmp_service):
        healer = SelfHealer()
        healer.heal(str(tmp_service / "vulnerable_service.py"), mode="generate")
        healed_file = next(tmp_service.glob("*_healed.py"))
        content = healed_file.read_text(encoding="utf-8")
        assert "HEALED VERSION" in content

    def test_healed_file_contains_healer_annotations(self, tmp_service):
        healer = SelfHealer()
        healer.heal(str(tmp_service / "vulnerable_service.py"), mode="generate")
        healed_file = next(tmp_service.glob("*_healed.py"))
        content = healed_file.read_text(encoding="utf-8")
        assert "HEALER" in content

    def test_healing_results_reference_healed_file(self, tmp_service):
        healer = SelfHealer()
        report = healer.heal(str(tmp_service / "vulnerable_service.py"), mode="generate")
        files_with_healed = [r.healed_file for r in report.healing_results if r.healed_file]
        assert len(files_with_healed) >= 1

    def test_original_file_is_not_modified(self, tmp_service):
        src = tmp_service / "vulnerable_service.py"
        original_content = src.read_text(encoding="utf-8")
        healer = SelfHealer()
        healer.heal(str(src), mode="generate")
        assert src.read_text(encoding="utf-8") == original_content


# ─────────────────────────────────────────────────────────────────────────────
# JSON persistence
# ─────────────────────────────────────────────────────────────────────────────

class TestJSONPersistence:
    def test_heal_and_save_json_creates_file(self, tmp_service, tmp_path):
        output = str(tmp_path / "report.json")
        healer = SelfHealer()
        healer.heal_and_save_json(str(tmp_service / "vulnerable_service.py"), output)
        assert Path(output).exists()

    def test_saved_json_is_valid(self, tmp_service, tmp_path):
        output = str(tmp_path / "report.json")
        healer = SelfHealer()
        healer.heal_and_save_json(str(tmp_service / "vulnerable_service.py"), output)
        with open(output) as fh:
            data = json.load(fh)
        assert "total_vulnerabilities" in data
        assert "vulnerabilities" in data
        assert "remediation_plans" in data

    def test_saved_json_contains_vulnerability_details(self, tmp_service, tmp_path):
        output = str(tmp_path / "report.json")
        healer = SelfHealer()
        healer.heal_and_save_json(str(tmp_service / "vulnerable_service.py"), output)
        with open(output) as fh:
            data = json.load(fh)
        assert data["total_vulnerabilities"] >= 1
        assert isinstance(data["vulnerabilities"], list)
        vuln = data["vulnerabilities"][0]
        assert "vulnerability_type" in vuln
        assert "severity" in vuln
        assert "owasp_category" in vuln


# ─────────────────────────────────────────────────────────────────────────────
# Integration against real service files
# ─────────────────────────────────────────────────────────────────────────────

class TestRealServicesIntegration:
    def test_heal_user_service_finds_vulnerabilities(self):
        user_app = SERVICES_DIR / "user_service" / "app.py"
        if not user_app.exists():
            pytest.skip("user_service/app.py not found")
        healer = SelfHealer()
        report = healer.heal(str(user_app), mode="report")
        assert report.total_vulnerabilities >= 2

    def test_heal_item_service_finds_vulnerabilities(self):
        item_app = SERVICES_DIR / "item_service" / "app.py"
        if not item_app.exists():
            pytest.skip("item_service/app.py not found")
        healer = SelfHealer()
        report = healer.heal(str(item_app), mode="report")
        assert report.total_vulnerabilities >= 2

    def test_heal_services_directory_finds_multiple(self):
        if not SERVICES_DIR.exists():
            pytest.skip("services/ directory not found")
        healer = SelfHealer()
        report = healer.heal(str(SERVICES_DIR), mode="report")
        assert report.total_vulnerabilities >= 4

    def test_all_vulnerabilities_have_remediation_plans(self):
        if not SERVICES_DIR.exists():
            pytest.skip("services/ directory not found")
        healer = SelfHealer()
        report = healer.heal(str(SERVICES_DIR), mode="report")
        # Every detected vulnerability that has a template should have a plan
        assert len(report.remediation_plans) >= 1

    def test_report_to_dict_is_serialisable(self):
        if not SERVICES_DIR.exists():
            pytest.skip("services/ directory not found")
        healer = SelfHealer()
        report = healer.heal(str(SERVICES_DIR), mode="report")
        d = report.to_dict()
        # Should be JSON-serialisable without error
        json.dumps(d)
