# ozzie-mandrill-ml Dockerfile
# BUG-0004: Running as root in container (CWE-250, CVSS 7.8, HIGH, Tier 2)
FROM python:3.12-slim

WORKDIR /app

# BUG-0005: Copying entire context including .env and secrets (CWE-200, CVSS 6.5, MEDIUM, Tier 3)
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

# BUG-0006: Exposing debug port alongside application port (CWE-489, CVSS 5.3, MEDIUM, Tier 3)
EXPOSE 8000
EXPOSE 5678

# BUG-0007: Debug mode enabled in production image via reload flag (CWE-489, CVSS 4.3, LOW, Tier 4)
ENV PYTHONDONTWRITEBYTECODE=1
ENV LOG_LEVEL=DEBUG

# RH-001: This looks like it exposes secrets but ENV is overridden at runtime via docker-compose
ENV SECRET_KEY=placeholder-replaced-at-runtime

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
