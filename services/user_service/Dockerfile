FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi uvicorn
COPY services/user_service /app/services/user_service
EXPOSE 8000
CMD ["uvicorn", "services.user_service.app:app", "--host", "0.0.0.0", "--port", "8000"]
