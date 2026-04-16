#!/usr/bin/env bash
# =============================================================================
# sanitize-postman.sh
#
# Patches a Postman collection JSON so EvoMaster 3.3.0's PostmanParser does
# not throw a NullPointerException on items with null/empty response arrays.
#
# The upstream crAPI collection (OWASP/crAPI) ships with empty response arrays
# on every request item.  PostmanParser.parseTestCases (PostmanParser.kt:172)
# dereferences the first response element without a null check, crashing
# EvoMaster before test generation begins.
#
# Fix: for every request item whose "response" is null or [], replace it with
# a minimal placeholder response (status "200", empty body).  This satisfies
# the parser without changing the request definitions that EvoMaster actually
# mutates.
#
# Usage:
#   bash scripts/sanitize-postman.sh <input.json> [output.json]
#
#   If output is omitted, the file is edited in place.
# =============================================================================
set -euo pipefail

INPUT="${1:?Usage: sanitize-postman.sh <input.json> [output.json]}"
OUTPUT="${2:-${INPUT}}"

python3 - "${INPUT}" "${OUTPUT}" <<'PYEOF'
import json, sys

inp, out = sys.argv[1], sys.argv[2]
with open(inp) as f:
    data = json.load(f)

# The collection may be wrapped in a top-level "collection" key (v2.1 export
# format) or be at the root level. EvoMaster's Postman parser expects root.
col = data.get("collection", data)

PLACEHOLDER_RESPONSE = [{
    "name": "Default",
    "originalRequest": None,
    "status": "OK",
    "code": 200,
    "header": [],
    "body": ""
}]

fixed = 0
def walk(items):
    global fixed
    for item in items:
        if "item" in item:
            walk(item["item"])
        else:
            resp = item.get("response")
            if resp is None or (isinstance(resp, list) and len(resp) == 0):
                # Clone placeholder and set originalRequest to this item's request
                pr = [dict(PLACEHOLDER_RESPONSE[0])]
                pr[0]["originalRequest"] = item.get("request")
                item["response"] = pr
                fixed += 1

walk(col.get("item", []))

# Normalize output to root-level collection object so EvoMaster can parse it.
normalized = col

with open(out, "w") as f:
    json.dump(normalized, f, indent=2)

print(f"[sanitize-postman] Patched {fixed} item(s) with placeholder responses → {out}")
PYEOF
