#!/usr/bin/env python3
"""
import_evomaster.py
-------------------
Reads an EvoMaster report.json and imports the detected faults
into the OWASP_TOP_10_API_VULNERABILITIES MySQL database.

Usage:
    python3 import_evomaster.py path/to/report.json

What it does:
    1. Reads the report.json from an EvoMaster blackbox test
    2. Extracts all fault codes (Fault100, Fault101, Fault205, H500)
    3. Maps them to OWASP Top 10 categories
    4. Inserts/updates subcategories and specific_vulnerabilities
    5. Adds a fault_codes column if it doesn't exist yet

Requirements:
    pip install mysql-connector-python
"""

import json
import sys
import os
from collections import defaultdict

try:
    import mysql.connector
except ImportError:
    print("ERROR: mysql-connector-python is not installed.")
    print("Run: pip install mysql-connector-python")
    sys.exit(1)


# =============================================================
# CONFIGURATION - update these to match your setup
# =============================================================
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",  # <-- enter your MySQL root password here, or leave empty to be prompted
    "database": "OWASP_TOP_10_API_VULNERABILITIES",
}

# =============================================================
# FAULT CODE → OWASP MAPPING
# Maps each EvoMaster fault code to an OWASP primary category,
# a subcategory name, and a vulnerability description.
# Add new fault codes here as EvoMaster evolves.
# =============================================================
FAULT_MAPPING = {
    "Fault100": {
        "primary_category_id": 8,   # API8: Security Misconfiguration
        "subcategory": "Server Error Handling",
        "vulnerability_name": "Unhandled Internal Crash",
        "description": (
            "EvoMaster triggered unhandled exceptions causing internal "
            "server crashes. This indicates missing error handling or "
            "input validation in server-side code."
        ),
        "mitigation": (
            "Implement global exception handlers. Validate all input "
            "before processing. Add try-catch blocks around critical "
            "service methods. Never expose stack traces to the client."
        ),
    },
    "Fault101": {
        "primary_category_id": 8,   # API8: Security Misconfiguration
        "subcategory": "API Schema Compliance",
        "vulnerability_name": "Response Schema Mismatch",
        "description": (
            "API responses did not match the declared OpenAPI schema. "
            "Issues include unknown status codes, invalid JSON bodies, "
            "wrong content types, and mismatched data types."
        ),
        "mitigation": (
            "Enforce response validation middleware. Use contract testing "
            "in CI/CD. Keep the OpenAPI spec in sync with implementation."
        ),
    },
    "Fault205": {
        "primary_category_id": 9,   # API9: Improper Inventory Management
        "subcategory": "API Documentation Coverage",
        "vulnerability_name": "Undocumented HTTP Status Code",
        "description": (
            "The API returned HTTP status codes not listed in the OpenAPI "
            "specification, indicating gaps in API documentation."
        ),
        "mitigation": (
            "Audit all endpoints and document every possible response "
            "status code. Add automated checks to flag undocumented "
            "responses during testing."
        ),
    },
    "H500": {
        "primary_category_id": 8,   # API8: Security Misconfiguration
        "subcategory": "Server Error Handling",
        "vulnerability_name": "HTTP 500 Internal Server Error",
        "description": (
            "The API returned HTTP 500, indicating an unhandled "
            "server-side failure triggered by unexpected input."
        ),
        "mitigation": (
            "Add input validation. Implement graceful error handling "
            "that returns proper 4xx codes for bad input instead of "
            "crashing with 500."
        ),
    },
}


def parse_report(report_path):
    """Parse report.json and extract fault summaries."""
    with open(report_path, "r") as f:
        data = json.load(f)

    # Collect: fault_code → { endpoint → { count, contexts[] } }
    faults = defaultdict(lambda: defaultdict(lambda: {"count": 0, "contexts": []}))

    for finding in data.get("faults", {}).get("foundFaults", []):
        operation = finding.get("operationId", "UNKNOWN")
        method, _, path = operation.partition(":")
        test_id = finding.get("testCaseId", "")

        for cat in finding.get("faultCategories", []):
            code = cat["code"]
            context = cat.get("context")
            fault_key = f"Fault{code}"

            faults[fault_key][operation]["count"] += 1
            if context:
                faults[fault_key][operation]["contexts"].append(context)

        # Detect H500 from test case name
        if "500" in test_id.lower() or "causes500" in test_id.lower():
            faults["H500"][operation]["count"] += 1
            faults["H500"][operation]["contexts"].append("HTTP 500 Internal Server Error")

    return faults


def import_to_db(faults):
    """Import parsed faults into MySQL."""
    # Prompt for password if not set
    if not DB_CONFIG["password"]:
        import getpass
        DB_CONFIG["password"] = getpass.getpass("MySQL password: ")

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # Step 1: Ensure fault_codes column exists
    cursor.execute("""
        SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME = 'specific_vulnerabilities'
          AND COLUMN_NAME = 'fault_codes'
    """, (DB_CONFIG["database"],))

    if cursor.fetchone()[0] == 0:
        print("Adding fault_codes column to specific_vulnerabilities...")
        cursor.execute("""
            ALTER TABLE specific_vulnerabilities
            ADD COLUMN fault_codes VARCHAR(255) DEFAULT NULL
        """)

    # Step 2: Process each fault code found in the report
    for fault_code, endpoints in faults.items():
        if fault_code not in FAULT_MAPPING:
            print(f"WARNING: Unknown fault code '{fault_code}' — skipping.")
            print(f"  Add it to FAULT_MAPPING in this script to include it.")
            continue

        mapping = FAULT_MAPPING[fault_code]
        total = sum(ep["count"] for ep in endpoints.values())
        endpoint_list = ", ".join(endpoints.keys())

        print(f"\n{fault_code}: {total} occurrences across {len(endpoints)} endpoints")

        # Ensure subcategory exists
        cursor.execute(
            "SELECT id FROM subcategories WHERE subcategory_name = %s AND primary_id = %s",
            (mapping["subcategory"], mapping["primary_category_id"]),
        )
        row = cursor.fetchone()
        if row:
            sub_id = row[0]
        else:
            cursor.execute(
                "INSERT INTO subcategories (primary_id, subcategory_name) VALUES (%s, %s)",
                (mapping["primary_category_id"], mapping["subcategory"]),
            )
            sub_id = cursor.lastrowid
            print(f"  Created subcategory: {mapping['subcategory']}")

        # Build description with endpoint details
        full_description = (
            f"{mapping['description']} "
            f"Found {total} occurrences across endpoints: {endpoint_list}."
        )

        # Check if vulnerability already exists for this fault code
        cursor.execute(
            "SELECT id FROM specific_vulnerabilities WHERE fault_codes = %s",
            (fault_code,),
        )
        existing = cursor.fetchone()

        if existing:
            # Update existing row with latest scan data
            cursor.execute("""
                UPDATE specific_vulnerabilities
                SET description = %s, subcategory_id = %s
                WHERE fault_codes = %s
            """, (full_description, sub_id, fault_code))
            print(f"  Updated: {mapping['vulnerability_name']}")
        else:
            # Insert new vulnerability
            cursor.execute("""
                INSERT INTO specific_vulnerabilities
                    (subcategory_id, vulnerability_name, description, mitigation, fault_codes)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                sub_id,
                mapping["vulnerability_name"],
                full_description,
                mapping["mitigation"],
                fault_code,
            ))
            print(f"  Inserted: {mapping['vulnerability_name']}")

    conn.commit()
    cursor.close()
    conn.close()
    print("\nDone! Verify with:")
    print("  SELECT p.category_name, s.subcategory_name, v.vulnerability_name, v.fault_codes")
    print("  FROM specific_vulnerabilities v")
    print("  JOIN subcategories s ON v.subcategory_id = s.id")
    print("  JOIN primary_categories p ON s.primary_id = p.id")
    print("  ORDER BY v.fault_codes;")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} path/to/report.json")
        sys.exit(1)

    report_path = sys.argv[1]
    if not os.path.exists(report_path):
        print(f"ERROR: File not found: {report_path}")
        sys.exit(1)

    print(f"Parsing {report_path}...")
    faults = parse_report(report_path)

    if not faults:
        print("No faults found in report.")
        sys.exit(0)

    print(f"Found fault codes: {', '.join(sorted(faults.keys()))}")
    import_to_db(faults)


if __name__ == "__main__":
    main()
