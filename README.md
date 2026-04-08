[APISec_Readme.txt](https://github.com/user-attachments/files/26570343/APISec_Readme.txt)
README: crAPI Deployment

C
### System Overview
Infrastructure: Digital Ocean Droplet


### Access Endpoints
Web Application: http://167.99.136.89:8888 (Car servicing platform)
Mailhog: http://167.99.136.89:8025 (Email interceptor for verification/resets)



### Installation Steps

## 1. Environment Preparation
Install the latest version of Docker and the unzip utility to handle the repository files.

# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Unzip
apt update && apt install unzip -y



## 2. Deploy crAPI
Download the latest main branch from the OWASP repository and prepare the Docker environment.

# Download and extract crAPI
curl -L -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip /tmp/crapi.zip -d /opt

# Navigate to deployment directory
cd /opt/crAPI-main/deploy/docker

# Pull container images
docker compose pull

# Start services in detached mode
LISTEN_IP="0.0.0.0" docker compose -f docker-compose.yml --compatibility up -d



### API Documentation & Testing

Openapi-spec (Used with editor.swagger.io to explore API endpoint behavior and examples)
https://raw.githubusercontent.com/OWASP/crAPI/main/openapi-spec/crapi-openapi-spec.json

Postman collection: https://crustyclappyblabby-5758839.postman.co/workspace/crustyclappyblabby's-Workspace~a6b17386-26a0-4f3b-8847-43858406173a/request/53316149-d4a736f2-16fe-4d70-ab98-1a933d577565?action=share&creator=53316149&ctx=documentation



### Tools

## EvoMaster

#See report
Start local python http server (in generated_tests folder!)
python -m http.server 8000

Open report
Localhost:8000 (in browser)


## Snyk - NOT API CLI!

# add Docker container to app.snyk.io
snyk container monitor <container:tag>

# Static Application Security Testing
Snyk code test
