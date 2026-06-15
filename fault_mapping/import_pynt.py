"""Import Pynt vulnerability findings into the OWASP mitigations database.

Parallel to import_evomaster.py. Reads one or more Pynt HTML reports,
parses the embedded findings, then inserts or updates rows in the
``mitigations`` table and writes a manifest file the GitHub Action
consumes to scaffold mitigation directories.

Usage:
    # Real run, writes to DB and manifest
    python3 fault_mapping/import_pynt.py path/to/results_pynt.html

    # Directory of reports (recursively scans for .html files)
    python3 fault_mapping/import_pynt.py path/to/pynt-reports/

    # Dry-run, manifest only, no DB
    python3 fault_mapping/import_pynt.py path/to/results_pynt.html --dry-run

    # Custom manifest location
    python3 fault_mapping/import_pynt.py path/to/results_pynt.html \\
            --manifest custom/path.json

Default manifest path: ``fault_mapping/manifests/repo_paths.json``,
shared with import_evomaster.py so the same GitHub Action can pick up
both parsers' output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Default manifest location, matched to import_evomaster.py.
DEFAULT_MANIFEST = Path("fault_mapping/manifests/repo_paths.json")

# DB connection defaults, matched to import_evomaster.py.
DB_NAME = "OWASP_TOP_10_API_VULNERABILITIES"


# ---------------------------------------------------------------------------
# Finding mapping
# ---------------------------------------------------------------------------
#
# Each entry maps a Pynt test-case name (the <span> text inside
# pynt-test-case-text) to:
#   - subcategory_name: the row in the ``subcategories`` DB table this
#       finding belongs to. Looked up at runtime, never hardcoded by id.
#   - owasp_tag: the 2023 OWASP API tag stored in the ``mitigations``
#       row. Both EvoMaster and Pynt parsers normalize to 2023 to match
#       the DB primary_categories and the mitigations repo directory
#       layout.
#   - primary_slug: the 2023 top-level directory in the mitigations
#       repo where this finding's mitigation will live.
#
# When Pynt emits a finding name not in this table, the parser falls
# back to UNCATEGORIZED_DEFAULT (API7 Security Misconfiguration). The
# fallback is logged so unknown findings are visible without breaking
# the run.

FINDING_MAPPING: dict[str, dict[str, str]] = {
    "Unsigned JWT": {
        "subcategory_name": "Unsigned JWT",
        "owasp_tag": "API2-2023",
        "primary_slug": "api2_broken_authentication",
    },
    "No signature validation in JWT": {
        "subcategory_name": "No Signature Validation In JWT",
        "owasp_tag": "API2-2023",
        "primary_slug": "api2_broken_authentication",
    },
    "Unbounded Repeats": {
        "subcategory_name": "Unbounded Repeats",
        "owasp_tag": "API4-2023",
        "primary_slug": "api4_unrestricted_resource_consumption",
    },
    "Remote resource access": {
        "subcategory_name": "Remote Resource Access",
        "owasp_tag": "API7-2023",
        "primary_slug": "api7_server_side_request_forgery",
    },
    "Exposed .env File": {
        "subcategory_name": "Exposed Env File",
        "owasp_tag": "API8-2023",
        "primary_slug": "api8_security_misconfiguration",
    },
    "Guessable resource identifier": {
        "subcategory_name": "Guessable Resource Identifier",
        "owasp_tag": "API8-2023",
        "primary_slug": "api8_security_misconfiguration",
    },
    "NoSQL Injection": {
        "subcategory_name": "NoSQL Injection",
        "owasp_tag": "API8-2023",
        "primary_slug": "api8_security_misconfiguration",
    },
    "CACHE-CONTROL Header Missing": {
        "subcategory_name": "CACHE-CONTROL Header Missing",
        "owasp_tag": "API8-2023",
        "primary_slug": "api8_security_misconfiguration",
    },
}

# Fallback for any Pynt finding name not in FINDING_MAPPING. The
# subcategory name will be the raw finding name itself, so an
# `add_pynt_subcategories.sql`-style insert may be needed. API8:2023
# Security Misconfiguration is the natural catch-all per the OWASP
# 2023 docs, which folded generic injection and misconfig issues into
# this category.
UNCATEGORIZED_DEFAULT = {
    "owasp_tag": "API8-2023",
    "primary_slug": "api8_security_misconfiguration",
}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Regex patterns for the Pynt HTML structure.
#
# Each finding is a <div class="pynt-issue-container"> block that
# contains both "What we found:" AND a pynt-finding-fix-it-text
# section. Passing tests use "What we tested:" and have no fix-it
# block, so they are filtered out.

ISSUE_CONTAINER_OPEN = re.compile(
    r'<div\s+class=["\']?pynt-issue-container["\']?[^>]*>',
)
SECTION_CLOSE = re.compile(r'</section>')

TEST_CASE_NAME = re.compile(
    r'<div class="pynt-test-case-text">\s*<span>([^<]+)</span>',
    re.DOTALL,
)
SEVERITY = re.compile(
    r'<span class="pynt-finding-status-title">([^<]+)</span>',
)
OWASP_LINK = re.compile(
    r'href="https://owasp\.org/API-Security/editions/(\d+)/en/0xa(\d+)-[^/"]+/?"',
)
ENDPOINT_INLINE = re.compile(r'<b>(\w+)\s+([^<]+)</b>')
DESCRIPTION = re.compile(
    r'What we found:\s*</div>\s*<div>(.+?)</div>',
    re.DOTALL,
)
FIX_IT = re.compile(
    r'<strong>Fix it!</strong>\s*<div>\s*(.+?)\s*</div>',
    re.DOTALL,
)
# Some findings list affected endpoints in a separate block instead of
# inline, e.g. CACHE-CONTROL Header Missing. The endpoints sit inside
# the pynt-explanations-container that follows the "Affected Endpoints"
# heading. We capture up to the next pynt-finding-fix-it-text or pynt-
# regular-details-container, whichever closes the section.
AFFECTED_ENDPOINTS_BLOCK = re.compile(
    r'<strong>Affected Endpoints</strong>'
    r'(.*?)'
    r'(?:pynt-finding-fix-it-text|pynt-regular-details-container|</section>)',
    re.DOTALL,
)


@dataclass
class PyntFinding:
    """One Pynt vulnerability finding extracted from the HTML report."""

    name: str
    severity: str | None
    owasp_year: str | None
    owasp_num: str | None
    description: str | None
    fix: str | None
    endpoints: list[tuple[str, str]] = field(default_factory=list)
    source_file: str | None = None


def _strip_html(text: str) -> str:
    """Remove inline HTML tags and collapse whitespace."""
    text = re.sub(r'<[^>]+>', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def parse_html_file(path: Path) -> list[PyntFinding]:
    """Parse all findings from a single Pynt HTML report file."""
    html = path.read_text(encoding="utf-8", errors="replace")
    findings: list[PyntFinding] = []

    # Split the document on issue-container openers, then process each
    # chunk independently. The first chunk (before the first container)
    # is discarded.
    chunks = ISSUE_CONTAINER_OPEN.split(html)[1:]
    for chunk in chunks:
        end = SECTION_CLOSE.search(chunk)
        body = chunk[: end.start()] if end else chunk

        # Real findings have both markers. Passing tests have neither.
        if "What we found:" not in body:
            continue
        if "pynt-finding-fix-it-text" not in body:
            continue

        name_m = TEST_CASE_NAME.search(body)
        if not name_m:
            continue
        name = name_m.group(1).strip()

        sev_m = SEVERITY.search(body)
        owasp_m = OWASP_LINK.search(body)
        desc_m = DESCRIPTION.search(body)
        fix_m = FIX_IT.search(body)

        # Endpoints, either inline in the description (<b>METHOD /path</b>),
        # or in a separate "Affected Endpoints" block listing many at once.
        endpoints: list[tuple[str, str]] = []
        inline = ENDPOINT_INLINE.search(body)
        if inline:
            endpoints.append((inline.group(1), inline.group(2).strip()))

        block_m = AFFECTED_ENDPOINTS_BLOCK.search(body)
        if block_m:
            block_text = _strip_html(block_m.group(1))
            # Lines look like "POST /a/b GET /c/d POST /e/f" after stripping HTML.
            for line_m in re.finditer(r'\b([A-Z]+)\s+(/\S+)', block_text):
                endpoints.append((line_m.group(1), line_m.group(2)))

        findings.append(
            PyntFinding(
                name=name,
                severity=sev_m.group(1).strip() if sev_m else None,
                owasp_year=owasp_m.group(1) if owasp_m else None,
                owasp_num=owasp_m.group(2) if owasp_m else None,
                description=_strip_html(desc_m.group(1)) if desc_m else None,
                fix=_strip_html(fix_m.group(1)) if fix_m else None,
                endpoints=endpoints,
                source_file=str(path),
            )
        )

    return findings


def parse_input_path(path: Path) -> list[PyntFinding]:
    """Parse one .html file or every .html file under a directory."""
    if path.is_file():
        return parse_html_file(path)
    if path.is_dir():
        all_findings: list[PyntFinding] = []
        for html_path in sorted(path.rglob("*.html")):
            all_findings.extend(parse_html_file(html_path))
        return all_findings
    raise FileNotFoundError(f"input path does not exist: {path}")


# ---------------------------------------------------------------------------
# Slugify and repo_path construction (matches import_evomaster.py)
# ---------------------------------------------------------------------------


def slugify(text: str) -> str:
    """Lowercase, collapse non-alphanumerics to underscore, trim edges."""
    slug = re.sub(r'[^a-z0-9]+', '_', text.lower())
    return slug.strip('_')


def make_repo_path(
    primary_slug: str,
    subcategory_name: str,
    vulnerability_name: str,
) -> str:
    """Build the canonical repo path for this finding's mitigation."""
    return (
        f"{primary_slug}/{slugify(subcategory_name)}/"
        f"{slugify(vulnerability_name)}/search_replace.json"
    )


# ---------------------------------------------------------------------------
# Finding -> mitigation row resolution
# ---------------------------------------------------------------------------


@dataclass
class ResolvedFinding:
    """A Pynt finding mapped to the canonical mitigations-row fields."""

    vulnerability_name: str
    subcategory_name: str
    owasp_tag: str
    primary_slug: str
    repo_path: str
    description: str
    severity: str | None
    endpoints: list[tuple[str, str]]
    source_files: list[str]
    was_uncategorized: bool


def resolve_findings(findings: Iterable[PyntFinding]) -> list[ResolvedFinding]:
    """Collapse Pynt findings to one ResolvedFinding per unique vulnerability.

    The same Pynt finding name appearing on multiple endpoints (e.g.
    Unsigned JWT on six endpoints) collapses to one mitigations row,
    one repo directory. Endpoint context is preserved in the resolved
    object but the DB stores one row per vulnerability_name, matching
    the EvoMaster importer's behavior.
    """
    by_name: dict[str, ResolvedFinding] = {}

    for f in findings:
        mapping = FINDING_MAPPING.get(f.name)
        was_uncategorized = mapping is None
        if mapping is None:
            mapping = {
                "subcategory_name": f.name,
                "owasp_tag": UNCATEGORIZED_DEFAULT["owasp_tag"],
                "primary_slug": UNCATEGORIZED_DEFAULT["primary_slug"],
            }
            print(
                f"WARNING: Pynt finding {f.name!r} not in FINDING_MAPPING, "
                f"defaulting to {mapping['owasp_tag']} "
                f"({mapping['primary_slug']})",
                file=sys.stderr,
            )

        vuln_name = f.name
        if vuln_name in by_name:
            entry = by_name[vuln_name]
            entry.endpoints.extend(f.endpoints)
            if f.source_file and f.source_file not in entry.source_files:
                entry.source_files.append(f.source_file)
            continue

        repo_path = make_repo_path(
            mapping["primary_slug"],
            mapping["subcategory_name"],
            vuln_name,
        )
        by_name[vuln_name] = ResolvedFinding(
            vulnerability_name=vuln_name,
            subcategory_name=mapping["subcategory_name"],
            owasp_tag=mapping["owasp_tag"],
            primary_slug=mapping["primary_slug"],
            repo_path=repo_path,
            description=f.description or "",
            severity=f.severity,
            endpoints=list(f.endpoints),
            source_files=[f.source_file] if f.source_file else [],
            was_uncategorized=was_uncategorized,
        )

    return list(by_name.values())


# ---------------------------------------------------------------------------
# DB access (lazy import, matches import_evomaster.py)
# ---------------------------------------------------------------------------


def _require_mysql():
    """Import mysql.connector lazily so --dry-run does not require it."""
    try:
        import mysql.connector  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            "mysql-connector-python not installed. "
            "Run `pip install mysql-connector-python` or use --dry-run."
        ) from exc
    import mysql.connector

    return mysql.connector


def lookup_subcategory(cursor, subcategory_name: str) -> int | None:
    """Resolve a subcategory_id by name, joining primary_categories."""
    cursor.execute(
        """
        SELECT s.id
        FROM subcategories s
        JOIN primary_categories p ON s.primary_id = p.id
        WHERE s.subcategory_name = %s
        """,
        (subcategory_name,),
    )
    row = cursor.fetchone()
    return row[0] if row else None


def import_to_db(
    resolved: list[ResolvedFinding],
    db_user: str,
    db_password: str,
    db_host: str = "localhost",
) -> dict[str, int]:
    """Insert or update mitigations rows for each resolved finding.

    Match by vulnerability_name. Preserve any existing repo_path that
    differs from the computed default and is not 'TBD', mirroring
    import_evomaster.py's manual-override behavior. Returns counts.
    """
    mysql = _require_mysql()
    counts = {"inserted": 0, "updated": 0, "skipped": 0}

    conn = mysql.connect(
        host=db_host, user=db_user, password=db_password, database=DB_NAME,
    )
    try:
        cursor = conn.cursor()
        for r in resolved:
            subcategory_id = lookup_subcategory(cursor, r.subcategory_name)
            if subcategory_id is None:
                print(
                    f"SKIP: subcategory {r.subcategory_name!r} not found in DB "
                    f"for vulnerability {r.vulnerability_name!r}. "
                    f"Add it via add_pynt_subcategories.sql and re-run.",
                    file=sys.stderr,
                )
                counts["skipped"] += 1
                continue

            cursor.execute(
                "SELECT id, repo_path FROM mitigations "
                "WHERE vulnerability_name = %s",
                (r.vulnerability_name,),
            )
            existing = cursor.fetchone()

            if existing is None:
                cursor.execute(
                    """
                    INSERT INTO mitigations
                        (subcategory_id, vulnerability_name, description,
                         owasp_tag, repo_path)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        subcategory_id,
                        r.vulnerability_name,
                        r.description,
                        r.owasp_tag,
                        r.repo_path,
                    ),
                )
                counts["inserted"] += 1
                continue

            mit_id, existing_path = existing
            new_path = r.repo_path
            if existing_path and existing_path not in ("TBD", new_path):
                # Manual override, preserve.
                print(
                    f"Note: kept existing repo_path {existing_path!r} for "
                    f"{r.vulnerability_name!r} (computed default was "
                    f"{new_path!r})",
                    file=sys.stderr,
                )
                new_path = existing_path

            cursor.execute(
                """
                UPDATE mitigations
                SET subcategory_id = %s,
                    description = %s,
                    owasp_tag = %s,
                    repo_path = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (
                    subcategory_id,
                    r.description,
                    r.owasp_tag,
                    new_path,
                    mit_id,
                ),
            )
            counts["updated"] += 1

        conn.commit()
    finally:
        conn.close()

    return counts


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def build_manifest(resolved: list[ResolvedFinding]) -> dict:
    """Build the manifest dict the GitHub Action consumes."""
    entries = []
    for r in resolved:
        entries.append(
            {
                "directory": r.repo_path.rsplit("/", 1)[0],
                "repo_path": r.repo_path,
                "vulnerability_name": r.vulnerability_name,
                "subcategory_name": r.subcategory_name,
                "owasp_tag": r.owasp_tag,
                "primary_slug": r.primary_slug,
                "source": "pynt",
            }
        )
    return {"entries": entries}


def write_manifest(
    resolved: list[ResolvedFinding],
    manifest_path: Path,
    dry_run: bool = False,
) -> None:
    """Serialize the manifest, merging with any existing entries.

    The manifest is shared with import_evomaster.py, so we read any
    existing entries, drop our own previous Pynt entries (matched by
    source == 'pynt'), and write the union back. EvoMaster entries are
    preserved untouched.
    """
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    existing_entries: list[dict] = []
    if manifest_path.exists():
        try:
            existing = json.loads(manifest_path.read_text())
            existing_entries = [
                e for e in existing.get("entries", [])
                if e.get("source") != "pynt"
            ]
        except json.JSONDecodeError:
            print(
                f"WARNING: existing manifest {manifest_path} is not valid "
                f"JSON, overwriting.",
                file=sys.stderr,
            )

    new_manifest = build_manifest(resolved)
    new_manifest["entries"] = existing_entries + new_manifest["entries"]
    if dry_run:
        new_manifest["dry_run"] = True

    manifest_path.write_text(json.dumps(new_manifest, indent=2) + "\n")
    print(
        f"Wrote {len(new_manifest['entries'])} total entries to "
        f"{manifest_path} ({len(new_manifest['entries']) - len(existing_entries)} "
        f"from Pynt)"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import Pynt vulnerability findings into the OWASP "
        "mitigations database.",
    )
    parser.add_argument(
        "input_path",
        type=Path,
        help="Path to a Pynt HTML report file or a directory of reports.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and write manifest only, do not touch the database.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help=f"Manifest output path (default: {DEFAULT_MANIFEST}).",
    )
    parser.add_argument(
        "--db-user", default="root",
        help="MySQL username (default: root).",
    )
    parser.add_argument(
        "--db-password", default="",
        help="MySQL password (default: empty, prompt-free).",
    )
    parser.add_argument(
        "--db-host", default="localhost",
        help="MySQL host (default: localhost).",
    )
    args = parser.parse_args(argv)

    findings = parse_input_path(args.input_path)
    print(f"Parsed {len(findings)} Pynt findings from {args.input_path}")

    resolved = resolve_findings(findings)
    print(f"Resolved to {len(resolved)} unique vulnerabilities")
    for r in resolved:
        endpoints_str = ", ".join(f"{m} {p}" for m, p in r.endpoints[:3])
        more = f" (+{len(r.endpoints) - 3} more)" if len(r.endpoints) > 3 else ""
        print(f"  - {r.vulnerability_name} [{r.owasp_tag}] -> {r.repo_path}")
        if endpoints_str:
            print(f"      endpoints: {endpoints_str}{more}")

    if args.dry_run:
        print("DRY RUN: skipping DB write.")
    else:
        counts = import_to_db(
            resolved,
            db_user=args.db_user,
            db_password=args.db_password,
            db_host=args.db_host,
        )
        print(
            f"DB: {counts['inserted']} inserted, "
            f"{counts['updated']} updated, "
            f"{counts['skipped']} skipped"
        )

    write_manifest(resolved, args.manifest, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
