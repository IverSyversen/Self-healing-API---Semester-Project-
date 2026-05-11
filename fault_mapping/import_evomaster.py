#!/usr/bin/env python3
"""
import_evomaster.py
-------------------
Reads EvoMaster's generated Java test files and imports the detected
faults into the OWASP_TOP_10_API_VULNERABILITIES MySQL database.

Also emits a manifest file (repo_paths.json) listing the repo_path
values that need to exist as directories in the mitigations Git repo.
A scheduled GitHub Action reads that manifest and creates the
directories with .gitkeep placeholders.

Usage:
    python3 import_evomaster.py path/to/em-tests-dir/ [--manifest path/to/repo_paths.json]
    python3 import_evomaster.py path/to/SingleFile_Test.java

What it does:
    1. Walks the input path for *.java files (or reads a single file)
    2. Parses each @Test method for fault docstrings and inline
        // FaultNNN. comments
    3. Maps each fault code to a subcategory (looked up by name at
        runtime) and an OWASP tag
    4. Builds a deterministic repo_path of the form
        <primary_slug>/<subcategory_slug>/<vulnerability_slug>/search_replace.json
    5. Inserts new rows into the `mitigations` table, or updates
        existing rows that share the same vulnerability_name
    6. Writes a manifest of repo_paths for the GitHub Action to consume

Requirements:
    pip install mysql-connector-python
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

try:
    import mysql.connector
    _HAS_MYSQL = True
except ImportError:
    mysql = None  # populated lazily
    _HAS_MYSQL = False


def _require_mysql():
    """Fail with a clear message only when the DB is actually needed."""
    if not _HAS_MYSQL:
        print("ERROR: mysql-connector-python is not installed.")
        print("Run: pip install mysql-connector-python")
        print("Or use --dry-run to skip the database step.")
        sys.exit(1)


# =============================================================
# CONFIGURATION
# =============================================================
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "OWASP_TOP_10_API_VULNERABILITIES",
}

DEFAULT_MANIFEST_PATH = "fault_mapping/manifests/repo_paths.json"
DEFAULT_VERSION = "main"
MITIGATION_FILENAME = "search_replace.json"


# =============================================================
# FAULT CODE -> mitigations row mapping
#
# subcategory_name is looked up against the subcategories table at
# runtime to resolve the foreign key for the mitigations row.
#
# primary_slug is the directory name in the mitigations repo (which
# uses OWASP API Top 10 2019 categories). This is hardcoded rather
# than derived from primary_categories.category_name because the DB
# uses 2023 labels while the mitigations repo uses 2019 directory
# names, and the project's source of truth is the repo layout.
#
# Note: in EvoMaster's Java output, Fault100 always carries an
# HTTP 500 detail line, so there is no separate H500 code needed.
# =============================================================
FAULT_MAPPING = {
    "Fault100": {
        "subcategory_name": "Server Error Handling",
        "vulnerability_name": "Unhandled Internal Crash",
        "owasp_tag": "API7-2019",
        "primary_slug": "api7_security_misconfiguration",
        "description": (
            "EvoMaster triggered unhandled exceptions causing HTTP 500 "
            "internal server errors. This indicates missing error "
            "handling or input validation in server-side code."
        ),
    },
    "Fault101": {
        "subcategory_name": "API Schema Compliance",
        "vulnerability_name": "Response Schema Mismatch",
        "owasp_tag": "API7-2019",
        "primary_slug": "api7_security_misconfiguration",
        "description": (
            "API responses did not match the declared OpenAPI schema. "
            "Issues include unknown status codes, invalid JSON bodies, "
            "wrong content types, and mismatched data types."
        ),
    },
    "Fault205": {
        "subcategory_name": "API Documentation Coverage",
        "vulnerability_name": "Undocumented HTTP Status Code",
        "owasp_tag": "API9-2019",
        "primary_slug": "api9_improper_asset_management",
        "description": (
            "The API returned HTTP status codes not listed in the "
            "OpenAPI specification, indicating gaps in API documentation."
        ),
    },
}


# =============================================================
# Regex patterns for parsing EvoMaster's Java output
# =============================================================

# Splits a Java source file on @Test annotations to isolate each test
# method along with the docstring above it. We capture everything from
# the preceding `/**` block down to the closing `}` of the method.
TEST_METHOD_BLOCK_RE = re.compile(
    r"/\*\*(?P<doc>.*?)\*/\s*"
    r"@Test\s*(?:@Timeout\([^)]*\))?\s*"
    r"public\s+void\s+(?P<name>\w+)\s*\([^)]*\)[^{]*\{"
    r"(?P<body>.*?)\n\s*\}",
    re.DOTALL,
)

# Type-codes line, two variants:
#   * Type-codes: 100, 101
#   * type-code 101
TYPE_CODES_RE = re.compile(
    r"[Tt]ype-codes?:?\s+([\d,\s]+)",
)

# Single Call line: (500) POST:/identity/api/auth/login
SINGLE_CALL_RE = re.compile(
    r"\(\s*(?P<status>\d{3})\s*\)\s*(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS):(?P<path>\S+)",
)

# Numbered call line: 3 - (401) POST:/identity/api/auth/login
NUMBERED_CALL_RE = re.compile(
    r"^\s*\*?\s*\d+\s*-\s*\(\s*(?P<status>\d{3})\s*\)\s*"
    r"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS):(?P<path>\S+)",
    re.MULTILINE,
)

# Inline fault comment: // Fault100. Some detail text.
INLINE_FAULT_RE = re.compile(
    r"//\s*Fault(?P<code>\d+)\.\s*(?P<detail>[^\n]+)",
)


# =============================================================
# Slug + path helpers
# =============================================================
def slugify(text):
    """Lowercase, underscore separated, alphanumeric only."""
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")


def make_repo_path(primary_slug, subcategory_name, vulnerability_name):
    """Build the canonical repo_path for a mitigation row.

    primary_slug is taken verbatim (hardcoded in FAULT_MAPPING) to
    match the 2019 directory naming in the mitigations repo.
    """
    return "/".join([
        primary_slug,
        slugify(subcategory_name),
        slugify(vulnerability_name),
        MITIGATION_FILENAME,
    ])


def directory_of(repo_path):
    return repo_path.rsplit("/", 1)[0]


# =============================================================
# Java parser
# =============================================================
def extract_triggering_call(docstring):
    """Pick the call most likely to have triggered the fault.

    For multi-step tests, the last numbered call is the one that
    produced the fault. For single-call tests, use that line.
    """
    numbered = list(NUMBERED_CALL_RE.finditer(docstring))
    if numbered:
        last = numbered[-1]
        return f"{last.group('method')}:{last.group('path')}"
    single = SINGLE_CALL_RE.search(docstring)
    if single:
        return f"{single.group('method')}:{single.group('path')}"
    return "UNKNOWN"


def extract_type_codes(docstring):
    """Pull declared fault codes from the docstring 'Type-codes' line."""
    m = TYPE_CODES_RE.search(docstring)
    if not m:
        return []
    return [c.strip() for c in m.group(1).split(",") if c.strip().isdigit()]


def parse_java_file(java_path):
    """Parse one .java file and yield (fault_key, operation, detail) tuples."""
    with open(java_path, "r", encoding="utf-8") as f:
        content = f.read()

    results = []

    for match in TEST_METHOD_BLOCK_RE.finditer(content):
        docstring = match.group("doc")
        body = match.group("body")

        operation = extract_triggering_call(docstring)
        declared_codes = set(extract_type_codes(docstring))

        # Inline comments are authoritative for the detail text.
        inline_matches = list(INLINE_FAULT_RE.finditer(body))
        seen_codes = set()

        for im in inline_matches:
            code = im.group("code")
            detail = im.group("detail").strip()
            seen_codes.add(code)
            results.append((f"Fault{code}", operation, detail))

        # If the docstring declared a fault code but no inline comment
        # confirmed it (rare, but possible if EvoMaster trims comments),
        # still record it with a generic detail so it is not lost.
        for code in declared_codes - seen_codes:
            results.append((f"Fault{code}", operation, "Declared in docstring only"))

    return results


def parse_input_path(input_path):
    """Walk a directory or single file and aggregate fault findings."""
    faults = defaultdict(lambda: defaultdict(lambda: {"count": 0, "contexts": []}))

    if os.path.isfile(input_path):
        java_files = [input_path] if input_path.endswith(".java") else []
    else:
        java_files = []
        for root, _, files in os.walk(input_path):
            for name in files:
                if name.endswith(".java"):
                    java_files.append(os.path.join(root, name))

    if not java_files:
        print(f"WARNING: no .java files found at {input_path}")
        return faults

    print(f"Scanning {len(java_files)} Java file(s)...")
    for jf in java_files:
        findings = parse_java_file(jf)
        if findings:
            print(f"  {os.path.basename(jf)}: {len(findings)} fault entries")
        for fault_key, operation, detail in findings:
            faults[fault_key][operation]["count"] += 1
            faults[fault_key][operation]["contexts"].append(detail)

    return faults


# =============================================================
# DB lookups
# =============================================================
def lookup_subcategory(cursor, subcategory_name):
    """Return (subcategory_id, primary_category_name) or (None, None)."""
    cursor.execute(
        """
        SELECT s.id, p.category_name
        FROM subcategories s
        JOIN primary_categories p ON s.primary_id = p.id
        WHERE s.subcategory_name = %s
        """,
        (subcategory_name,),
    )
    row = cursor.fetchone()
    if row:
        return row[0], row[1]
    return None, None


# =============================================================
# Main import
# =============================================================
def write_manifest(manifest_entries, manifest_path, source_path):
    """Serialize the manifest to disk. Independent of DB writes."""
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_path": source_path,
        "entries": manifest_entries,
    }
    os.makedirs(os.path.dirname(manifest_path) or ".", exist_ok=True)
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest written to: {manifest_path}")
    print(f"  ({len(manifest_entries)} repo_path entries)")


def build_manifest_only(faults, source_path):
    """Build manifest entries without touching the DB.

    Used by --dry-run, returns the list of entries that would be
    written. primary_category_name is set to a placeholder since we
    cannot look it up without a DB connection.
    """
    entries = []
    for fault_code, endpoints in faults.items():
        if fault_code not in FAULT_MAPPING:
            print(f"WARNING: Unknown fault code '{fault_code}', skipping.")
            continue

        mapping = FAULT_MAPPING[fault_code]
        total = sum(ep["count"] for ep in endpoints.values())

        # In dry-run mode, the path is built from the mapping alone,
        # no DB lookup needed.
        repo_path = make_repo_path(
            mapping["primary_slug"],
            mapping["subcategory_name"],
            mapping["vulnerability_name"],
        )

        print(f"\n{fault_code}: {total} occurrences across {len(endpoints)} endpoints")
        print(f"  (dry-run) repo_path: {repo_path}")

        entries.append({
            "fault_code": fault_code,
            "vulnerability_name": mapping["vulnerability_name"],
            "owasp_tag": mapping["owasp_tag"],
            "subcategory_name": mapping["subcategory_name"],
            "primary_category_name_2023": "(dry-run, not looked up)",
            "primary_slug_2019": mapping["primary_slug"],
            "repo_path": repo_path,
            "directory": directory_of(repo_path),
            "occurrences": total,
            "endpoints": sorted(endpoints.keys()),
            "dry_run": True,
        })

    return entries


def import_to_db(faults, manifest_path, source_path):
    """Import parsed faults into mitigations and emit a manifest."""
    _require_mysql()
    if not DB_CONFIG["password"]:
        import getpass
        DB_CONFIG["password"] = getpass.getpass("MySQL password: ")

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    inserted = 0
    updated = 0
    skipped = 0
    manifest_entries = []

    for fault_code, endpoints in faults.items():
        if fault_code not in FAULT_MAPPING:
            print(f"WARNING: Unknown fault code '{fault_code}', skipping.")
            print(f"  Add it to FAULT_MAPPING in this script to include it.")
            skipped += 1
            continue

        mapping = FAULT_MAPPING[fault_code]
        total = sum(ep["count"] for ep in endpoints.values())
        endpoint_list = ", ".join(sorted(endpoints.keys()))

        print(f"\n{fault_code}: {total} occurrences across {len(endpoints)} endpoints")

        sub_id, primary_name = lookup_subcategory(cursor, mapping["subcategory_name"])
        if sub_id is None:
            print(
                f"  ERROR: subcategory '{mapping['subcategory_name']}' "
                f"not found in subcategories table, skipping {fault_code}."
            )
            skipped += 1
            continue

        repo_path = make_repo_path(
            mapping["primary_slug"],
            mapping["subcategory_name"],
            mapping["vulnerability_name"],
        )

        full_description = (
            f"{mapping['description']} "
            f"Found {total} occurrences across endpoints: {endpoint_list}."
        )

        cursor.execute(
            "SELECT id, repo_path FROM mitigations WHERE vulnerability_name = %s",
            (mapping["vulnerability_name"],),
        )
        existing = cursor.fetchone()

        if existing:
            existing_id, existing_path = existing
            if existing_path == repo_path or not existing_path or existing_path == "TBD":
                cursor.execute(
                    """
                    UPDATE mitigations
                    SET description = %s,
                        subcategory_id = %s,
                        owasp_tag = %s,
                        repo_path = %s
                    WHERE id = %s
                    """,
                    (full_description, sub_id, mapping["owasp_tag"], repo_path, existing_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE mitigations
                    SET description = %s,
                        subcategory_id = %s,
                        owasp_tag = %s
                    WHERE id = %s
                    """,
                    (full_description, sub_id, mapping["owasp_tag"], existing_id),
                )
                print(
                    f"  Note: kept existing repo_path '{existing_path}' "
                    f"(differs from computed '{repo_path}')."
                )
                repo_path = existing_path
            print(f"  Updated: {mapping['vulnerability_name']}")
            updated += 1
        else:
            cursor.execute(
                """
                INSERT INTO mitigations
                    (subcategory_id, vulnerability_name, description,
                     owasp_tag, repo_path, version)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    sub_id,
                    mapping["vulnerability_name"],
                    full_description,
                    mapping["owasp_tag"],
                    repo_path,
                    DEFAULT_VERSION,
                ),
            )
            print(f"  Inserted: {mapping['vulnerability_name']}")
            print(f"    repo_path: {repo_path}")
            inserted += 1

        manifest_entries.append({
            "fault_code": fault_code,
            "vulnerability_name": mapping["vulnerability_name"],
            "owasp_tag": mapping["owasp_tag"],
            "subcategory_name": mapping["subcategory_name"],
            "primary_category_name_2023": primary_name,
            "primary_slug_2019": mapping["primary_slug"],
            "repo_path": repo_path,
            "directory": directory_of(repo_path),
            "occurrences": total,
            "endpoints": sorted(endpoints.keys()),
        })

    conn.commit()
    cursor.close()
    conn.close()

    write_manifest(manifest_entries, manifest_path, source_path)

    print(f"\nSummary: {inserted} inserted, {updated} updated, {skipped} skipped.")
    print("\nNext steps:")
    print(f"  1. Commit {manifest_path} to your mitigations repo.")
    print(f"  2. The nightly GitHub Action will create any missing directories.")


def main():
    parser = argparse.ArgumentParser(
        description="Import EvoMaster Java test output into OWASP DB.",
    )
    parser.add_argument(
        "input_path",
        help="Path to a directory of EvoMaster .java files, or a single .java file",
    )
    parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST_PATH,
        help=f"Where to write the repo_paths manifest (default: {DEFAULT_MANIFEST_PATH})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Parse and write the manifest only, do not touch the database. "
            "Useful for testing the parser and manifest format."
        ),
    )
    args = parser.parse_args()

    if not os.path.exists(args.input_path):
        print(f"ERROR: Path not found: {args.input_path}")
        sys.exit(1)

    print(f"Parsing {args.input_path}...")
    faults = parse_input_path(args.input_path)

    if not faults:
        print("No faults found.")
        write_manifest([], args.manifest, args.input_path)
        sys.exit(0)

    print(f"\nFound fault codes: {', '.join(sorted(faults.keys()))}")

    if args.dry_run:
        print("\n*** DRY RUN, skipping database writes ***")
        entries = build_manifest_only(faults, args.input_path)
        write_manifest(entries, args.manifest, args.input_path)
        print("\nDone. Re-run without --dry-run to write to the database.")
        return

    import_to_db(faults, args.manifest, args.input_path)


if __name__ == "__main__":
    main()
