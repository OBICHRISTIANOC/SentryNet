FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend and frontend source code
COPY backend /app/backend
COPY frontend /app/frontend

WORKDIR /app/backend

# Set environment defaults
ENV PORT=5000
ENV SERVE_FRONTEND=1
ENV SENTRYNET_ALLOWED_ORIGIN="*"

EXPOSE 5000

# Start Gunicorn server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
