# CaptainDreadPipe Environmental Monitoring Dashboard
# Julia 1.10 / Genie.jl

# BUG (no inline marker — Dockerfile issues are infrastructure-level):
# These are tracked in the manifest but not inline-marked per convention for non-Julia files.

# Uses full base image instead of slim — larger attack surface
FROM julia:1.10

# Sets working directory
WORKDIR /app

# Copies everything including .git, secrets, etc.
COPY . /app

# Install dependencies
RUN julia -e 'using Pkg; Pkg.activate("."); Pkg.instantiate()'

# Precompile
RUN julia -e 'using Pkg; Pkg.activate("."); Pkg.precompile()'

# Create required directories
RUN mkdir -p /app/data /app/uploads /app/reports /tmp/captain-dread-pipe && \
    chmod 777 /tmp/captain-dread-pipe

# Expose port
EXPOSE 8080

# Run as root (should use non-root user)
# No USER directive — container runs as root

# No health check defined
# No resource limits

# Start the application
ENV JULIA_ENV=production
ENV BIND_ADDRESS=0.0.0.0

CMD ["julia", "--project=.", "src/app.jl"]
