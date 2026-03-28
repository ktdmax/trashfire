FROM rustlang/rust:nightly AS builder

WORKDIR /app

COPY . .

# BUG-0131: Building with RUSTFLAGS that disable stack protection and overflow checks (CWE-120, CVSS 7.5, CRITICAL, Tier 1)
ENV RUSTFLAGS="-C overflow-checks=no -C debug-assertions=no"

RUN cargo build --release

# BUG-0132: Final image based on ubuntu instead of distroless/scratch — large attack surface (CWE-1104, CVSS 5.3, MEDIUM, Tier 3)
FROM ubuntu:22.04

# BUG-0133: Installing curl, wget, netcat in production image — unnecessary attack tools (CWE-1104, CVSS 5.3, MEDIUM, Tier 3)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    netcat \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/elaine-marley-mesh /app/elaine-marley-mesh
COPY config/ /etc/mesh/

# BUG-0135: Running as root in container — container escape gives host root access (CWE-250, CVSS 7.5, HIGH, Tier 2)
# Should have: USER nonroot:nonroot

EXPOSE 8080 9090

# BUG-0137: Environment variables with secrets baked into image layer (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
ENV MESH_ADMIN_TOKEN="mesh-admin-secret-token-2024"
ENV REDIS_PASSWORD="r3dis-s3cret!"
ENV MESH_CONFIG_PATH="/etc/mesh/config.yaml"
ENV RUST_LOG="trace"
ENV RUST_BACKTRACE="full"



ENTRYPOINT ["/app/elaine-marley-mesh"]
