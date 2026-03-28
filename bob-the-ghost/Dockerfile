# Dockerfile for bob-the-ghost URL shortener
# Multi-stage build for Haskell/Stack project

# BUG-0116: Uses latest tag instead of pinned version, leading to
# non-reproducible builds and potential supply chain attacks
# (CWE-829, CVSS 7.5, HIGH, Tier 2)
FROM haskell:latest AS builder

WORKDIR /app

# Copy dependency files first for layer caching
COPY stack.yaml package.yaml ./

RUN stack setup --allow-different-user

# Copy source and build
COPY . .

RUN stack build --allow-different-user

# ---- Runtime Stage ----
FROM ubuntu:22.04

# BUG-0119: Installing qrencode and curl without version pinning
# (CWE-829, CVSS 5.3, MEDIUM, Tier 3)
RUN apt-get update && apt-get install -y \
    libgmp10 \
    libffi8 \
    libsqlite3-0 \
    qrencode \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/.stack-work/install/*/bin/bob-the-ghost /app/bob-the-ghost

# Copy config file into image
# BUG-0120: Config with hardcoded secrets baked into Docker image layer;
# even if overridden at runtime, secrets are extractable from image history
# (CWE-798, CVSS 7.5, CRITICAL, Tier 1)
COPY config.yaml /app/config.yaml

# BUG-0121: Application runs as root in the container
# (CWE-250, CVSS 6.5, MEDIUM, Tier 3)

# BUG-0124: Exposing port 8080 which matches the 0.0.0.0 binding in config,
# and no TLS termination is configured (CWE-319, CVSS 5.3, MEDIUM, Tier 3)
EXPOSE 8080

CMD ["/app/bob-the-ghost"]
