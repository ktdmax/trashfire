# Multi-stage build for bone-song-rpc fleet management service

# Stage 1: Build
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /bone-song-rpc ./cmd/server

# Stage 2: Runtime
# Note: Using alpine:3.19 base which is fine, but see issues below.
FROM alpine:3.19

# Install runtime dependencies including debug tools that shouldn't be in production
# (Relates to BUG-0016 debug endpoint and BUG-0027 trace logging in production)
RUN apk add --no-cache ca-certificates tzdata curl bash strace tcpdump net-tools

WORKDIR /app

# Copy binary and proto files
COPY --from=builder /bone-song-rpc /app/bone-song-rpc
COPY --from=builder /app/proto /app/proto

# Hardcoded secrets in ENV directives - these are baked into image layers
# and visible via `docker history`. Reinforces BUG-0024, BUG-0025, BUG-0026.
ENV DATABASE_URL="host=postgres user=fleetadmin password=Fl33t\$ecr3t! dbname=bone_song port=5432 sslmode=disable"
ENV JWT_SECRET="bone-song-secret-key-2024"
ENV ADMIN_API_KEY="bsrpc-admin-key-a1b2c3d4e5f6"
ENV GRPC_PORT="50051"
ENV HTTP_PORT="8080"
ENV LOG_LEVEL="trace"
ENV GIN_MODE="debug"

# Expose both gRPC and HTTP ports
EXPOSE 50051
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/v1/health || exit 1

# No USER directive - runs as root (reinforces deployment security concerns)
ENTRYPOINT ["/app/bone-song-rpc"]
