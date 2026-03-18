# Self-Healing API – Semester Project

A proof-of-concept **detect → map → fix** lifecycle for API vulnerabilities in a microservice-based application.

---

## Overview

This project demonstrates how recurring API vulnerabilities can be:

1. **Detected** – by a static code scanner (and optionally a dynamic HTTP probe)
2. **Mapped** – to semi-universal, template-driven remediation plans
3. **Fixed** – automatically (where safe) or annotated for human review

The remediation logic is **not hardcoded** to any single service: all fix guidance lives in JSON templates in `remediation/templates/`, so extending the system to new vulnerability classes requires only a new template file.

### OWASP API Security Top 10 categories covered

| Vulnerability | OWASP Category | Severity |
|---|---|---|
| SQL Injection | API10:2023 – Unsafe Consumption of APIs | CRITICAL |
| Broken Authentication | API2:2023 – Broken Authentication | HIGH |
| BOLA / IDOR | API1:2023 – Broken Object Level Authorization | HIGH |
| Excessive Data Exposure | API3:2023 – Broken Object Property Level Auth | MEDIUM |
| Missing Rate Limiting | API4:2023 – Unrestricted Resource & Rate Limiting | MEDIUM |

---

## Repository layout

```
.
├── services/
│   ├── user_service/        # FastAPI user service (intentionally vulnerable)
│   └── item_service/        # FastAPI item service (intentionally vulnerable)
│
├── vulnerability_scanner/
│   ├── scanner.py           # StaticCodeScanner + DynamicAPIScanner
│   └── vulnerability_types.py
│
├── remediation/
│   ├── engine.py            # Template-driven RemediationEngine
│   └── templates/           # JSON remediation templates (one per vulnerability type)
│       ├── sql_injection.json
│       ├── broken_auth.json
│       ├── bola.json
│       ├── excessive_data_exposure.json
│       └── missing_rate_limiting.json
│
├── self_healer/
│   └── healer.py            # SelfHealer – orchestrates detect→map→fix
│
├── tests/                   # pytest test suite (62 tests)
│   ├── test_scanner.py
│   ├── test_remediation.py
│   └── test_self_healer.py
│
├── docker-compose.yml
└── requirements.txt
```

---

## Quick start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the test suite

```bash
pytest tests/ -v
```

### 3. Run a healing cycle from the command line

```python
from self_healer.healer import SelfHealer

healer = SelfHealer()

# Report mode – detect & map, no files written
report = healer.heal("services/", mode="report")
report.print_summary()

# Generate mode – also writes a *_healed.py next to each vulnerable file
report = healer.heal("services/user_service/app.py", mode="generate")
report.print_summary()

# Persist the full JSON report
healer.heal_and_save_json("services/", "healing_report.json")
```

### 4. Run the microservices with Docker Compose

```bash
docker compose up --build
# User service → http://localhost:8001/docs
# Item service → http://localhost:8002/docs
```

> **Warning**: The services are intentionally vulnerable. Do not deploy them in any environment outside of local development or a controlled lab.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        SelfHealer                            │
│                                                              │
│   DETECT                  MAP                    FIX         │
│  ─────────        ──────────────────      ──────────────     │
│  Static/         RemediationEngine        Generate           │
│  Dynamic    ──►  loads JSON template ──►  annotated          │
│  Scanner         for each finding         *_healed.py        │
│                                           or JSON report     │
└──────────────────────────────────────────────────────────────┘
        │                                         │
  ┌─────┴──────┐                        ┌─────────┴────────┐
  │ user-svc   │                        │ item-svc          │
  │ (vulns ×4) │                        │ (vulns ×4)        │
  └────────────┘                        └──────────────────┘
```

### Healing modes

| Mode | Description |
|---|---|
| `report` | Detect and map only. Prints a structured summary. No files modified. Suitable as a CI/CD gate. |
| `generate` | As above, plus writes a `*_healed.py` alongside each vulnerable source file containing inline `# HEALER:` annotations and any safe automatic substitutions. |

A third `apply` mode (rewrite originals in-place, run tests, commit) is described in `self_healer/healer.py` as **future work**.

---

## Extending the system

### Adding a new vulnerability type

1. Add the new type to `VulnerabilityType` and `OWASP_MAPPING` in `vulnerability_scanner/vulnerability_types.py`.
2. Add a detection pattern to the appropriate `_*_PATTERNS` list in `vulnerability_scanner/scanner.py`.
3. Create `remediation/templates/<new_type>.json` with `fix_description`, `patch_steps`, `verification_rules`, and `references`.
4. Register the template filename in `remediation/engine.py::_TEMPLATE_FILES`.
5. Write tests in `tests/`.

### Integrating external scanners (EvoMaster, RESTler)

`DynamicAPIScanner` in `vulnerability_scanner/scanner.py` provides a programmatic interface for runtime probing. A future integration could:

* Parse EvoMaster/RESTler output (JSON/SARIF) into `VulnerabilityReport` objects.
* Feed those reports directly into `RemediationEngine.get_plans_for_all()`.
* Apply the resulting plans via `SelfHealer`.

---

## Security note

The microservices in `services/` contain **intentional** security vulnerabilities (SQL injection, missing authentication, BOLA, excessive data exposure, missing rate limiting). They exist solely to provide a concrete "ground truth" for the proof of concept. Never deploy them in a real or internet-facing environment.
