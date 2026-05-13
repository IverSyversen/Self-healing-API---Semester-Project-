# Copilot Instructions for this Repository

## Build, test, and lint commands

### White-box EvoMaster workflow (primary workflow in this repo)

```bash
# One-time environment setup on droplet/host (installs Java 17, Maven, Docker, EvoMaster, builds artifacts)
sudo bash scripts/setup-droplet.sh

# Build EvoMaster driver JAR only
mvn -f evomaster-driver/pom.xml package -DskipTests

# Build crAPI identity-service.jar + jwks.json (downloads upstream crAPI source and applies local patch first)
bash scripts/build-community-jar.sh

# Validate runtime prerequisites before running white-box session
bash scripts/preflight-check.sh

# Generate tests with EvoMaster white-box mode
bash scripts/run-whitebox.sh --time 60 --output ./generated_tests

# Compile/run generated tests and produce Surefire HTML report
bash scripts/run-report.sh --tests-dir ./generated_tests --sut-base-url http://localhost:8080
```

### Run a single generated test class

After `run-report.sh` has copied generated tests into `test-runner/src/test/java`:

```bash
mvn -f test-runner/pom.xml \
  -DSUT_BASE_URL=http://localhost:8080 \
  -Dtest='<GeneratedTestClassName>' \
  -Dsurefire.failIfNoSpecifiedTests=false \
  test
```

### Self-healing pipeline

```bash
pip install -r self-healing-pipeline/requirements.txt
cd self-healing-pipeline
python -m pipeline.orchestrator --config pipeline-config.json
```

### Linting

No dedicated lint command/config is currently defined in this repository.

## High-level architecture

- This repo does **not** instrument the Go `crapi-community` service directly. White-box instrumentation targets the Java `identity-service` JAR, launched by the EvoMaster driver (`evomaster-driver/src/main/java/org/evomaster/driver/CrApiCommunityController.java`).
- `scripts/run-whitebox.sh` orchestrates the end-to-end run: starts infra containers (`postgres`, `mongodb`, `mailhog`), stops Docker `crapi-identity`, launches the instrumented host-side identity JAR through the driver, runs EvoMaster, and writes artifacts to `generated_tests/`.
- `docker-compose.evomaster.yml` is intentionally adjusted for this mode: DBs are exposed on localhost for the host-run identity JAR; `crapi-identity` is expected to be stopped during white-box runs.
- `scripts/run-report.sh` bridges generated tests into the Maven `test-runner` module, executes JUnit 5 tests via Surefire, and publishes `generated_tests/surefire-report.html`.
- `self-healing-pipeline/` is a separate Python orchestration layer: scanners (`pipeline/scanners/*`) -> normalization (`normalizer.py`) -> SQLite persistence (`db.py`) -> mitigation application (`pipeline/mitigations/registry.py` with `mitigations.json`) -> verification (`verifier.py`).

## Key conventions in this codebase

- **Security-focused EvoMaster flags are treated as baseline**, not optional tuning, in `scripts/run-whitebox.sh` (e.g. `--security`, `--schemaOracles`, taint/discovered-info settings).
- **Patched/sanitized inputs are part of normal operation**:  
  - OpenAPI is patched for EvoMaster compatibility (`postman/crapi-openapi-spec-patched.json`, optional regeneration in `run-whitebox.sh`).  
  - Postman seed collections are sanitized through `scripts/sanitize-postman.sh` before use.
- **Driver reset is data-seeding heavy by design**: `resetStateOfSUT()` reseeds deterministic users and domain data (vehicles, OTP/token/profile-video rows) every cycle so EvoMaster can reach deep authenticated/security flows.
- **Schema-aware seed user insertion supports multiple crAPI DB schemas**: current schema path inserts into `user_login` + `user_details` with sequences, with a legacy fallback insert path.
- **Self-healing pipeline contracts rely on shared vuln_type strings** across scanners, `normalizer.py`, `mitigations.json`, and verification rules; keep these mappings in sync when adding new finding types.
- **Findings de-duplication logic is stateful** in SQLite (`db.upsert_finding`): duplicate `(scanner, vuln_type, endpoint, method)` findings are reused unless prior status is `VERIFIED`.
