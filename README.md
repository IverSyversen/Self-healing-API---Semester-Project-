# README: crAPI Deployment

[APISec_Readme.txt](https://github.com/user-attachments/files/26570343/APISec_Readme.txt)

## System Overview

Infrastructure: Digital Ocean Droplet

## Access Endpoints

- Web Application: http://167.99.136.89:8888 (Car servicing platform)
- Mailhog: http://167.99.136.89:8025 (Email interceptor for verification/resets)

## Installation Steps

### 1. Environment Preparation

Install the latest version of Docker and the unzip utility to handle the repository files.

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Unzip
apt update && apt install unzip -y
```

### 2. Deploy crAPI

Download the latest main branch from the OWASP repository and prepare the Docker environment.

```bash
# Download and extract crAPI
curl -L -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip /tmp/crapi.zip -d /opt

# Navigate to deployment directory
cd /opt/crAPI-main/deploy/docker

# Pull container images
docker compose pull

# Start services in detached mode
LISTEN_IP="0.0.0.0" docker compose -f docker-compose.yml --compatibility up -d
```

## API Documentation & Testing

**OpenAPI spec** (use with [editor.swagger.io](https://editor.swagger.io) to explore API endpoint behavior and examples):
https://raw.githubusercontent.com/OWASP/crAPI/main/openapi-spec/crapi-openapi-spec.json

**Postman collection**: https://crustyclappyblabby-5758839.postman.co/workspace/crustyclappyblabby's-Workspace~a6b17386-26a0-4f3b-8847-43858406173a/request/53316149-d4a736f2-16fe-4d70-ab98-1a933d577565?action=share&creator=53316149&ctx=documentation

## Tools

### EvoMaster – Black-Box Mode (existing)

See report: start a local Python HTTP server from the `generated_tests` folder, then open `http://localhost:8000` in a browser.

```bash
python -m http.server 8000
```

### EvoMaster – White-Box Mode

White-box mode instruments the **crAPI identity service** JVM bytecode at runtime,
giving EvoMaster branch-level feedback to guide test generation far beyond what is
possible with black-box HTTP fuzzing alone.

> **Note:** The crAPI community service is written in **Go** and cannot be
> instrumented by EvoMaster's Java agent.  The identity service (Java / Spring Boot,
> port 8080) is used as the white-box testing target instead.

#### Architecture

```
DigitalOcean Droplet
├── Docker Compose (docker-compose.evomaster.yml)
│   ├── MongoDB, PostgreSQL, Mailhog
│   ├── crapi-community, crapi-workshop, crapi-web
│   └── crapi-identity  ← stopped during white-box run (port freed for EvoMaster)
├── EvoMaster Driver (Java, port 40100)
│   └── spawns → identity-service.jar  ← with -javaagent:evomaster-agent.jar
└── EvoMaster CLI  ← connects to driver, generates JUnit 5 test suite
```

#### One-time Setup (run as root on the droplet)

```bash
# Clone this repository on the droplet
git clone <repo-url> /opt/crapi-evomaster
cd /opt/crapi-evomaster

# Install Java 17, Maven, download EvoMaster artifacts, build driver + identity JAR
sudo bash scripts/setup-droplet.sh
```

This script:
1. Installs **Java 17** and **Maven** if not already present
2. Downloads `evomaster.jar` and `evomaster-agent.jar` to `/opt/evomaster/`
3. Fetches the crAPI **identity** service source (Java/Spring Boot), builds it with the bundled Gradle wrapper, and installs the fat JAR at `/opt/crapi/identity-service.jar` plus `jwks.json`
4. Builds the EvoMaster driver fat JAR at `evomaster-driver/target/crapi-community-driver-1.0.0.jar`

#### Running a White-Box Test Session

```bash
# Default: 60-minute budget, output to ./generated_tests
bash scripts/run-whitebox.sh

# Custom budget and output directory
bash scripts/run-whitebox.sh --time 30 --output /opt/results/evomaster
```

The script:
1. Starts the crAPI Docker stack (all services) via `docker-compose.evomaster.yml`
2. Stops the `crapi-identity` Docker container so port 8080 is free
3. Starts the EvoMaster driver; the driver spawns the identity service JAR with the agent
4. Runs the EvoMaster CLI in white-box mode for the specified time budget
5. Writes a **JUnit 5 test suite** + HTML report to the output directory
6. Automatically restores the Docker identity container on exit

#### Viewing the Report

```bash
cd generated_tests
python3 -m http.server 8000
# Open http://<droplet-ip>:8000 in a browser
```

#### Key Files

| File | Purpose |
|---|---|
| `evomaster-driver/pom.xml` | Maven project for the EvoMaster driver |
| `evomaster-driver/src/…/CrApiCommunityController.java` | `ExternalSutController` implementation |
| `docker-compose.evomaster.yml` | Docker Compose with identity service managed externally |
| `scripts/setup-droplet.sh` | One-time droplet setup (Java, Maven, artifacts, driver build) |
| `scripts/download-evomaster.sh` | Downloads EvoMaster CLI and agent JARs |
| `scripts/build-community-jar.sh` | Builds the crAPI identity service fat JAR |
| `scripts/run-whitebox.sh` | Orchestrates a full white-box test-generation run |

#### White-Box vs Black-Box

| | Black-box | White-box |
|---|---|---|
| Source code access | Not required | Identity service JAR instrumented |
| Coverage feedback | None | Branch-level (bytecode) |
| Test quality | HTTP-level | Deeper: explores internal branches |
| Setup complexity | Low | Medium (Java build required) |

### Snyk (NOT the API CLI)

```bash
# Add Docker container to app.snyk.io
snyk container monitor <container:tag>

# Static Application Security Testing
snyk code test
```
