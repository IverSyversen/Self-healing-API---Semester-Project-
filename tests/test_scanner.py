"""
Tests for the static code scanner.

The tests exercise the scanner against deliberately crafted Python snippets
and against the actual vulnerable service source files that ship with this
project.
"""
import os
import tempfile
import pytest
from pathlib import Path

from vulnerability_scanner.scanner import StaticCodeScanner, _find_sensitive_keys
from vulnerability_scanner.vulnerability_types import VulnerabilityType, Severity

SERVICES_DIR = Path(__file__).parent.parent / "services"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_tmp(source: str) -> str:
    """Write *source* to a temporary .py file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(source)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# SQL Injection
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLInjectionDetection:
    """Scanner correctly flags SQL injection patterns."""

    def test_fstring_in_execute(self):
        source = """
db.execute(f"SELECT * FROM users WHERE username = '{username}'")
"""
        path = _write_tmp(source)
        reports = StaticCodeScanner().scan_file(path)
        os.unlink(path)
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.SQL_INJECTION in types

    def test_concatenation_in_execute(self):
        source = """
db.execute("SELECT * FROM items WHERE id = " + str(item_id))
"""
        path = _write_tmp(source)
        reports = StaticCodeScanner().scan_file(path)
        os.unlink(path)
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.SQL_INJECTION in types

    def test_safe_parameterised_query_not_flagged(self):
        source = """
db.execute("SELECT * FROM users WHERE username = ?", (username,))
"""
        path = _write_tmp(source)
        reports = StaticCodeScanner().scan_file(path)
        os.unlink(path)
        sql_reports = [r for r in reports if r.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert sql_reports == []

    def test_severity_is_critical(self):
        source = 'db.execute(f"SELECT * FROM x WHERE id = \'{uid}\'")\n'
        path = _write_tmp(source)
        reports = StaticCodeScanner().scan_file(path)
        os.unlink(path)
        sql_reports = [r for r in reports if r.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert all(r.severity == Severity.CRITICAL for r in sql_reports)

    def test_report_contains_line_number(self):
        source = "# line 1\n# line 2\ndb.execute(f\"SELECT * FROM t WHERE x='{v}'\")\n"
        path = _write_tmp(source)
        reports = StaticCodeScanner().scan_file(path)
        os.unlink(path)
        sql_reports = [r for r in reports if r.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert sql_reports
        assert sql_reports[0].line_number is not None


# ─────────────────────────────────────────────────────────────────────────────
# Excessive Data Exposure
# ─────────────────────────────────────────────────────────────────────────────

class TestExcessiveDataExposureDetection:
    def test_password_field_detected(self):
        source = """
return {"id": row["id"], "username": row["username"], "password": row["password"]}
"""
        path = _write_tmp(source)
        reports = StaticCodeScanner().scan_file(path)
        os.unlink(path)
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.EXCESSIVE_DATA_EXPOSURE in types

    def test_secret_field_detected(self):
        source = 'return {"secret": item["secret"], "name": item["name"]}\n'
        path = _write_tmp(source)
        reports = StaticCodeScanner().scan_file(path)
        os.unlink(path)
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.EXCESSIVE_DATA_EXPOSURE in types


# ─────────────────────────────────────────────────────────────────────────────
# Missing Rate Limiting
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimitDetection:
    def test_search_endpoint_flagged(self):
        source = """
@app.post('/items/search')
def search_items(req: SearchRequest):
    pass
"""
        path = _write_tmp(source)
        reports = StaticCodeScanner().scan_file(path)
        os.unlink(path)
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.MISSING_RATE_LIMITING in types


# ─────────────────────────────────────────────────────────────────────────────
# Scanning actual service source files
# ─────────────────────────────────────────────────────────────────────────────

class TestScanRealServices:
    """Integration tests against the intentionally vulnerable demo services."""

    def test_user_service_has_sql_injection(self):
        user_app = SERVICES_DIR / "user_service" / "app.py"
        if not user_app.exists():
            pytest.skip("user_service/app.py not found")
        reports = StaticCodeScanner().scan_file(str(user_app))
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.SQL_INJECTION in types

    def test_user_service_has_excessive_data_exposure(self):
        user_app = SERVICES_DIR / "user_service" / "app.py"
        if not user_app.exists():
            pytest.skip("user_service/app.py not found")
        reports = StaticCodeScanner().scan_file(str(user_app))
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.EXCESSIVE_DATA_EXPOSURE in types

    def test_item_service_has_sql_injection(self):
        item_app = SERVICES_DIR / "item_service" / "app.py"
        if not item_app.exists():
            pytest.skip("item_service/app.py not found")
        reports = StaticCodeScanner().scan_file(str(item_app))
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.SQL_INJECTION in types

    def test_item_service_has_missing_rate_limiting(self):
        item_app = SERVICES_DIR / "item_service" / "app.py"
        if not item_app.exists():
            pytest.skip("item_service/app.py not found")
        reports = StaticCodeScanner().scan_file(str(item_app))
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.MISSING_RATE_LIMITING in types

    def test_item_service_has_excessive_data_exposure(self):
        item_app = SERVICES_DIR / "item_service" / "app.py"
        if not item_app.exists():
            pytest.skip("item_service/app.py not found")
        reports = StaticCodeScanner().scan_file(str(item_app))
        types = [r.vulnerability_type for r in reports]
        assert VulnerabilityType.EXCESSIVE_DATA_EXPOSURE in types

    def test_scan_directory_finds_multiple_vulnerabilities(self):
        if not SERVICES_DIR.exists():
            pytest.skip("services/ directory not found")
        reports = StaticCodeScanner().scan_directory(str(SERVICES_DIR))
        assert len(reports) >= 3, "Expected at least 3 vulnerabilities across service files"

    def test_reports_have_required_fields(self):
        user_app = SERVICES_DIR / "user_service" / "app.py"
        if not user_app.exists():
            pytest.skip("user_service/app.py not found")
        reports = StaticCodeScanner().scan_file(str(user_app))
        assert reports
        for r in reports:
            assert r.vulnerability_type is not None
            assert r.severity is not None
            assert r.location
            assert r.description
            assert r.evidence
            assert r.owasp_category
            assert r.remediation_hint


# ─────────────────────────────────────────────────────────────────────────────
# Helper function tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFindSensitiveKeys:
    def test_finds_password_in_flat_dict(self):
        obj = {"id": 1, "username": "alice", "password": "hash"}
        found = _find_sensitive_keys(obj, ["password"])
        assert "password" in found

    def test_finds_nested_sensitive_key(self):
        obj = {"user": {"id": 1, "secret": "abc"}}
        found = _find_sensitive_keys(obj, ["secret"])
        assert "secret" in found

    def test_finds_key_in_list(self):
        obj = [{"id": 1, "token": "tok"}, {"id": 2, "token": "tok2"}]
        found = _find_sensitive_keys(obj, ["token"])
        assert "token" in found

    def test_returns_empty_for_safe_response(self):
        obj = {"id": 1, "username": "alice", "email": "a@b.com"}
        found = _find_sensitive_keys(obj, ["password", "secret", "token"])
        assert found == []

    def test_case_insensitive_matching(self):
        obj = {"Password": "hash"}
        found = _find_sensitive_keys(obj, ["password"])
        assert "Password" in found
