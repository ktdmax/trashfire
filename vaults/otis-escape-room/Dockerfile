# otis-escape-room Dockerfile
# BUG-0006: Running as root in container, no USER directive (CWE-250, CVSS 6.5, MEDIUM, Tier 3)
FROM python:3.12-slim

WORKDIR /app

# BUG-0007: Copying .env and secrets into image layer (CWE-798, CVSS 7.5, HIGH, Tier 2)
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

# BUG-0008: Debug mode enabled in production container (CWE-489, CVSS 5.3, MEDIUM, Tier 3)
ENV DEBUG=true
ENV PYTHONUNBUFFERED=1
# BUG-0009: Database credentials hardcoded in Dockerfile ENV (CWE-798, CVSS 8.6, HIGH, Tier 2)
ENV DATABASE_URL=postgresql://otis_admin:EscapeR00m!2024@db:5432/escaperoom
ENV STRIPE_SECRET_KEY=sk_live_51ABC123DEF456GHI789JKL0
ENV STRIPE_WEBHOOK_SECRET=whsec_test_placeholder
ENV JWT_SECRET=super-secret-jwt-key-do-not-share
ENV RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672//
ENV REDIS_URL=redis://redis:6379/0

# BUG-0010: Exposing debug port alongside app port (CWE-200, CVSS 3.7, LOW, Tier 4)
EXPOSE 8000
EXPOSE 5678

# RH-001: Looks like shell injection via CMD but $PORT isn't user-controlled in Dockerfile context
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
