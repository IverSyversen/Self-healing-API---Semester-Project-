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

### EvoMaster

See report: start a local Python HTTP server from the `generated_tests` folder, then open `http://localhost:8000` in a browser.

```bash
python -m http.server 8000
```

### Snyk (NOT the API CLI)

```bash
# Add Docker container to app.snyk.io
snyk container monitor <container:tag>

# Static Application Security Testing
snyk code test
```
