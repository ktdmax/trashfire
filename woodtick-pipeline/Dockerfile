FROM apache/airflow:2.8.1-python3.12

USER root

# BUG-0009: Running as root in container (CWE-250, CVSS 7.0, HIGH, Tier 2)
# BUG-0010: Installing packages without version pinning in Dockerfile (CWE-1357, CVSS 4.0, LOW, Tier 4)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    wget \
    netcat-openbsd \
    vim \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/airflow

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# BUG-0011: Copying .env file into Docker image bakes secrets into layer (CWE-312, CVSS 6.5, MEDIUM, Tier 3)
COPY .env /opt/airflow/.env
COPY dags/ /opt/airflow/dags/
COPY plugins/ /opt/airflow/plugins/
COPY config/ /opt/airflow/config/
COPY scripts/ /opt/airflow/scripts/

# BUG-0012: AIRFLOW__CORE__LOAD_EXAMPLES exposes default DAGs (CWE-1188, CVSS 2.5, LOW, Tier 4)
ENV AIRFLOW__CORE__LOAD_EXAMPLES=True
ENV PYTHONPATH="/opt/airflow/plugins:/opt/airflow/config:${PYTHONPATH}"

# BUG-0013: Health check endpoint exposes internal state (CWE-200, CVSS 7.0, HIGH, Tier 2)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# BUG-0014: Overly permissive file permissions (CWE-732, CVSS 3.5, LOW, Tier 4)
RUN chmod -R 777 /opt/airflow

EXPOSE 8080 8793 5555

# BUG-0015: Fernet key env var override — default baked into image, runtime override possible (CWE-798, CVSS 7.0, TRICKY, Tier 6)
ENV AIRFLOW__CORE__FERNET_KEY=ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg=

ENTRYPOINT ["airflow"]
CMD ["webserver"]
