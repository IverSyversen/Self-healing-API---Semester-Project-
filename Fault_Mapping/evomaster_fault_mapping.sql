-- ============================================
-- EvoMaster Fault Mapping (v2)
-- Adds fault codes directly to the
-- specific_vulnerabilities table
-- ============================================

USE OWASP_TOP_10_API_VULNERABILITIES;

-- ============================================
-- Step 1: Add fault_codes column
-- ============================================

ALTER TABLE specific_vulnerabilities
  ADD COLUMN fault_codes VARCHAR(255) DEFAULT NULL;

-- ============================================
-- Step 2: Add missing subcategories
-- (API1 and API2 already have some)
-- ============================================

INSERT INTO subcategories (primary_id, subcategory_name) VALUES
  (8, 'Server Error Handling'),
  (8, 'API Schema Compliance'),
  (9, 'API Documentation Coverage'),
  (2, 'OTP and Password Reset');

-- ============================================
-- Step 3: Insert vulnerabilities with fault codes
-- ============================================

-- Fault100 → API8: Security Misconfiguration → Server Error Handling
INSERT INTO specific_vulnerabilities (subcategory_id, vulnerability_name, description, mitigation, fault_codes)
VALUES (
  (SELECT id FROM subcategories WHERE subcategory_name = 'Server Error Handling'),
  'Unhandled Internal Crash',
  'EvoMaster triggered unhandled exceptions causing internal server crashes across 11 endpoints (23 occurrences). Affected services include OTP validation, video processing, password reset, and email token verification.',
  'Implement global exception handlers. Validate all input before processing. Add try-catch blocks around critical service methods. Never expose stack traces to the client.',
  'Fault100'
);

-- Fault101 → API8: Security Misconfiguration → API Schema Compliance
INSERT INTO specific_vulnerabilities (subcategory_id, vulnerability_name, description, mitigation, fault_codes)
VALUES (
  (SELECT id FROM subcategories WHERE subcategory_name = 'API Schema Compliance'),
  'Response Schema Mismatch',
  'API responses did not match the OpenAPI specification across 19 endpoints (64 occurrences). Issues include unknown status codes, invalid JSON bodies, wrong content types, and mismatched data types.',
  'Enforce response validation middleware that checks all outgoing responses against the OpenAPI spec. Use contract testing in CI/CD. Keep the spec in sync with the actual implementation.',
  'Fault101'
);

-- Fault205 → API9: Improper Inventory Management → API Documentation Coverage
INSERT INTO specific_vulnerabilities (subcategory_id, vulnerability_name, description, mitigation, fault_codes)
VALUES (
  (SELECT id FROM subcategories WHERE subcategory_name = 'API Documentation Coverage'),
  'Undocumented HTTP Status Code',
  'The POST /identity/api/auth/login endpoint returned an HTTP status code not listed in the OpenAPI specification (1 occurrence). This indicates gaps in API documentation.',
  'Audit all endpoints and document every possible response status code in the OpenAPI spec. Add automated checks to flag undocumented responses during testing.',
  'Fault205'
);

-- H500 → API8: Security Misconfiguration → Server Error Handling
INSERT INTO specific_vulnerabilities (subcategory_id, vulnerability_name, description, mitigation, fault_codes)
VALUES (
  (SELECT id FROM subcategories WHERE subcategory_name = 'Server Error Handling'),
  'HTTP 500 Internal Server Error',
  'EvoMaster triggered HTTP 500 responses on OTP check endpoints (3 occurrences): POST /identity/api/auth/v2/check-otp and POST /identity/api/auth/v3/check-otp.',
  'Add input validation on OTP endpoints. Implement graceful error handling that returns proper 4xx codes for bad input instead of crashing with 500.',
  'H500'
);
