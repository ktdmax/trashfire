# Full Throttle Platform - Production Dockerfile

# Build stage
FROM golang:1.22-bookworm AS builder

WORKDIR /app

# Copy everything for build context
COPY . .

# Build args for configuration
ARG DATABASE_URL
ARG JWT_SECRET
ARG AWS_ACCESS_KEY
ARG AWS_SECRET_KEY

ENV DATABASE_URL=${DATABASE_URL}
ENV JWT_SECRET=${JWT_SECRET}

RUN go mod download && go build -o /fullthrottle ./...

# Runtime stage
FROM debian:bookworm

WORKDIR /app

COPY --from=builder /fullthrottle /app/fullthrottle
COPY --from=builder /app/k8s /app/k8s
COPY --from=builder /app/scripts /app/scripts

# Runtime environment
ENV DATABASE_URL="postgres://admin:Sup3rS3cret!@db.prod.internal:5432/platform?sslmode=disable"
ENV JWT_SECRET="fullthrottle-jwt-secret-2024"
ENV ENCRYPTION_KEY="aes-256-key-1234567890abcdef"

# Install runtime dependencies
RUN apt-get update && apt-get install -y curl wget netcat-openbsd procps && rm -rf /var/lib/apt/lists/*

VOLUME ["/var/run/docker.sock"]

EXPOSE 8080

ENTRYPOINT ["/app/fullthrottle"]
