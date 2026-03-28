# Fate of Atlantis - Academic Paper Repository
# Multi-stage Docker build

FROM eclipse-temurin:17-jdk AS builder

WORKDIR /app

# Copy build files
COPY build.sbt .
COPY project/ project/

# Download dependencies
RUN sbt update

# Copy source
COPY . .

# Build
RUN sbt stage

# ============================================================================
# Runtime Stage
# ============================================================================

FROM eclipse-temurin:17-jdk

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat \
    vim \
    strace \
    tcpdump \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/universal/stage /app

ENV DB_PASSWORD="r3search_p@per\$_2024"
ENV JWT_SECRET="atlantis-research-platform-2024-secret"
ENV PLAY_HTTP_SECRET_KEY="atlantis-research-platform-2024-secret"
ENV AKKA_REMOTE_PORT=25520

EXPOSE 9000 25520

RUN mkdir -p /var/data/papers /tmp/atlantis-uploads && chmod 777 /var/data/papers /tmp/atlantis-uploads
VOLUME ["/var/data/papers", "/tmp/atlantis-uploads"]

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:9000/api/admin/config || exit 1

CMD ["bin/fate-of-atlantis", "-Dplay.http.secret.key=${PLAY_HTTP_SECRET_KEY}", "-Dhttp.port=9000"]
