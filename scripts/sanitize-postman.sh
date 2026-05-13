#!/usr/bin/env bash
# =============================================================================
# sanitize-postman.sh
#
# Patches a Postman collection JSON so EvoMaster's PostmanParser works
# correctly.  Three categories of problems are fixed:
#
# 1. NULL/EMPTY RESPONSE ARRAYS
#    The upstream crAPI collection ships with empty response arrays on every
#    request item.  PostmanParser dereferences the first response element
#    without a null check, crashing EvoMaster before test generation begins.
#    Fix: replace null/[] with a minimal placeholder response.
#
# 2. UNRESOLVED POSTMAN TEMPLATE VARIABLES
#    The collection uses Postman environment variables ({{email}}, {{password}},
#    {{url}}, {{vehicle_id}}, {{VIN}}, {{PIN}}, etc.).  EvoMaster's parser logs
#    "Attempt to set enum parameter SCHEMA_EXAMPLES with non-enum value {{email}}"
#    and silently discards those seed requests — so EvoMaster gets NO example
#    input from the Postman collection, missing the entire point of seeding.
#    Fix: substitute every {{variable}} with a real concrete value from a
#    built-in seed dictionary before EvoMaster reads the file.
#
# 3. UNPARSEABLE / SCHEMA-KEYWORD BODIES
#    Some items use multipart/form-data raw bodies (binary upload) or JSON
#    bodies containing oneOf/anyOf/allOf schema keywords.  EvoMaster 5.x
#    PostmanParser maps these to ChoiceGene objects which
#    updateGenesRecursivelyWithParameterValue cannot process, throwing:
#      IllegalStateException: Unexpected gene found in RestCallAction: ChoiceGene
#    Fix: silently drop those items from the seed corpus (they are a tiny
#    minority; the rest of the collection seeds correctly).
#
# Usage:
#   bash scripts/sanitize-postman.sh <input.json> [output.json]
#
#   If output is omitted, the file is edited in place.
#
# Environment variables (override defaults):
#   CRAPI_URL          Base URL of the crAPI instance (default: http://localhost:8080)
#   SEED_EMAIL         Primary test user email   (default: alice@evomaster.test)
#   SEED_PASSWORD      Primary test user password (default: Passw0rd!1A)
#   SEED_EMAIL2        Secondary user email       (default: bob@evomaster.test)
# =============================================================================
set -euo pipefail

INPUT="${1:?Usage: sanitize-postman.sh <input.json> [output.json]}"
OUTPUT="${2:-${INPUT}}"

# Export env vars so the Python heredoc can access them.
export CRAPI_URL="${CRAPI_URL:-http://localhost:8080}"
export SEED_EMAIL="${SEED_EMAIL:-alice@evomaster.test}"
export SEED_PASSWORD="${SEED_PASSWORD:-Passw0rd!1A}"
export SEED_EMAIL2="${SEED_EMAIL2:-bob@evomaster.test}"

python3 - "${INPUT}" "${OUTPUT}" <<'PYEOF'
import json, os, re, sys

inp, out = sys.argv[1], sys.argv[2]

# ---------------------------------------------------------------------------
# Variable substitution dictionary
# Keys are Postman variable names (without {{ }}).
# Values are concrete strings EvoMaster can use as seed examples.
# ---------------------------------------------------------------------------
BASE_URL = os.environ.get("CRAPI_URL", "http://localhost:8080")
EMAIL    = os.environ.get("SEED_EMAIL",    "alice@evomaster.test")
PASS     = os.environ.get("SEED_PASSWORD", "Passw0rd!1A")
EMAIL2   = os.environ.get("SEED_EMAIL2",   "bob@evomaster.test")

VARS = {
    # Network / URL
    "url":              BASE_URL,
    "base_url":         BASE_URL,
    "baseUrl":          BASE_URL,
    "host":             BASE_URL,

    # Auth
    "email":            EMAIL,
    "username":         EMAIL,
    "user_email":       EMAIL,
    "email2":           EMAIL2,
    "password":         PASS,
    "new_password":     PASS,
    "token":            "",          # placeholder; EvoMaster replaces via login

    # Vehicle
    "vehicle_id":       "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1",
    "vehicleId":        "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1",
    "VIN":              "1HGEM21303L000001",
    "vin":              "1HGEM21303L000001",
    "PIN":              "000001",
    "pin":              "000001",
    "pincode":          "000001",

    # OTP / verification
    "OTP":              "000000",
    "otp":              "000000",
    "email_token":      "evomaster-email-token",

    # Video / media
    "video_id":         "1",
    "videoId":          "1",
    "video_name":       "seed-video-1.mp4",
    "conversion_params":"--verbose",

    # Community / posts
    "post_id":          "1",
    "postId":           "1",
    "comment":          "test comment",

    # Shop / workshop
    "product_id":       "1",
    "order_id":         "1",
    "coupon_code":      "TRAC075",
    "mechanic_id":      "1",

    # User profile
    "name":             "Alice EM",
    "phone_number":     "+15550001111",
    "number":           "+15550001111",
    "phone":            "+15550001111",
    "available_credit": "10000.0",

    # Email change flow
    "new_email":        "alice.new@evomaster.test",
    "old_email":        EMAIL,

    # Admin / privileged
    "adminToken":       "",          # placeholder; real token obtained via login
    "mechanicToken":    "",          # placeholder; real token obtained via login
    "admin_email":      "admin@evomaster.test",

    # Report / mechanic
    "report_id":        "1",
    "mechanic_api":     "1",
    "service_request_id": "1",

    # URL variants
    "url_mail":         "http://localhost:8025",   # MailHog
    "mail_url":         "http://localhost:8025",

    # Postman dynamic variables (resolved to deterministic test-safe values)
    "$randomIP":            "127.0.0.1",
    "$randomLoremSentence": "test sentence for evomaster",
    "$randomLoremParagraph":"test paragraph for evomaster",
    "$randomLoremWord":     "testword",
    "$randomFirstName":     "Alice",
    "$randomLastName":      "Test",
    "$randomFullName":      "Alice Test",
    "$randomEmail":         "random@evomaster.test",
    "$randomInt":           "42",
    "$randomFloat":         "3.14",
    "$randomBoolean":       "true",
    "$randomUUID":          "c0c0c0c0-c0c0-c0c0-c0c0-c0c0c0c0c0c0",
    "$randomUrl":           "http://localhost:8080",
    "$guid":                "d0d0d0d0-d0d0-d0d0-d0d0-d0d0d0d0d0d0",
    "$timestamp":           "1700000000",
    "$isoTimestamp":        "2023-11-14T00:00:00.000Z",
    "$randomPhoneNumber":   "+15550009999",
    "$randomAlphaNumeric":  "abc123",
    "$randomNoun":          "vehicle",
    "$randomHexadecimal":   "FF0000",
    "$randomUserName":      "evomaster_user",
    "$randomPassword":      PASS,
    "$randomJobTitle":      "Engineer",
    "$randomCity":          "TestCity",
    "$randomCountry":       "US",
    "$randomStreetAddress": "123 Test Street",
    "$randomZipCode":       "12345",

    # Generic / catch-all
    "id":               "1",
    "status":           "active",
}

def substitute(text):
    """Replace all {{var}} occurrences using the VARS dictionary."""
    def _replace(m):
        key = m.group(1).strip()
        return VARS.get(key, m.group(0))  # leave unknown vars unchanged
    return re.sub(r'\{\{([^}]+)\}\}', _replace, text)

def walk_and_patch(obj):
    """Recursively walk the collection object, substituting variables in
    strings and fixing empty response arrays."""
    if isinstance(obj, dict):
        return {k: walk_and_patch(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [walk_and_patch(item) for item in obj]
    elif isinstance(obj, str):
        return substitute(obj)
    else:
        return obj

with open(inp) as f:
    data = json.load(f)

# The collection may be wrapped in a top-level "collection" key (v2.1 export
# format) or be at the root level. EvoMaster's Postman parser expects root.
col = data.get("collection", data)

# ---- Pass 1: substitute all {{variable}} placeholders ----
col = walk_and_patch(col)
subst_done = True  # always runs

# ---- Pass 2: fix null/empty response arrays ----
PLACEHOLDER_RESPONSE = [{
    "name": "Default",
    "originalRequest": None,
    "status": "OK",
    "code": 200,
    "header": [],
    "body": ""
}]

fixed_resp = 0
def fix_responses(items):
    global fixed_resp
    for item in items:
        if "item" in item:
            fix_responses(item["item"])
        else:
            resp = item.get("response")
            if resp is None or (isinstance(resp, list) and len(resp) == 0):
                pr = [dict(PLACEHOLDER_RESPONSE[0])]
                pr[0]["originalRequest"] = item.get("request")
                item["response"] = pr
                fixed_resp += 1

fix_responses(col.get("item", []))

# ---- Pass 3: drop request items whose body would crash EvoMaster's PostmanParser ----
# Two categories are dropped:
# a) Bodies whose parsed JSON contains oneOf/anyOf/allOf — EvoMaster maps these
#    to ChoiceGene which updateGenesRecursivelyWithParameterValue cannot handle.
# b) Non-JSON raw bodies (multipart/form-data, binary blobs, etc.) — EvoMaster
#    cannot extract seed values from raw multipart content and may crash trying.
SCHEMA_KEYWORDS = {"oneOf", "anyOf", "allOf"}

def has_schema_keyword(obj):
    """Return True if obj (any JSON value) contains a oneOf/anyOf/allOf key."""
    if isinstance(obj, dict):
        if SCHEMA_KEYWORDS & obj.keys():
            return True
        return any(has_schema_keyword(v) for v in obj.values())
    if isinstance(obj, list):
        return any(has_schema_keyword(v) for v in obj)
    return False

def item_body_is_problematic(item):
    """Return True if this item's request body should be dropped."""
    try:
        req = item.get("request", {})
        body = req.get("body", {}) if isinstance(req, dict) else {}
        if not isinstance(body, dict):
            return False
        raw = body.get("raw", "")
        if not raw or not raw.strip():
            return False
        stripped = raw.strip()
        # Non-JSON body (multipart, binary, etc.) — drop it
        if not stripped.startswith(("{", "[")):
            return True
        # JSON body — check for schema keywords that create ChoiceGene
        try:
            parsed = json.loads(stripped)
            return has_schema_keyword(parsed)
        except json.JSONDecodeError:
            # Unparseable body — drop it to be safe
            return True
    except (AttributeError, TypeError):
        return False

dropped = 0
def drop_problematic_items(items):
    global dropped
    keep = []
    for item in items:
        if "item" in item:
            item["item"] = drop_problematic_items(item["item"])
            keep.append(item)
        elif item_body_is_problematic(item):
            dropped += 1
        else:
            keep.append(item)
    return keep

col["item"] = drop_problematic_items(col.get("item", []))

with open(out, "w") as f:
    json.dump(col, f, indent=2)

print(f"[sanitize-postman] Variable substitution: done")
print(f"[sanitize-postman] Patched {fixed_resp} item(s) with placeholder responses")
print(f"[sanitize-postman] Dropped {dropped} item(s) with non-JSON or oneOf/anyOf/allOf body schemas → {out}")
PYEOF
