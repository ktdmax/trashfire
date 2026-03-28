# PrintShop - Print-on-Demand Order Management
# Perl 5.38 + Mojolicious + ImageMagick

# Stage 1: Build
FROM perl:5.38-threaded AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libmysqlclient-dev \
    imagemagick \
    libmagickwand-dev \
    ghostscript \
    && rm -rf /var/lib/apt/lists/*

# Install Perl dependencies
COPY cpanfile /app/cpanfile
RUN cpanm --installdeps --notest .

# Copy application
COPY . /app/

# Stage 2: Runtime
FROM perl:5.38-threaded

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libmysqlclient-dev \
    imagemagick \
    ghostscript \
    mysql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# The ImageMagick policy below IS restrictive and blocks dangerous coders.
# This looks exploitable but the policy is correctly configured.
COPY <<'POLICY' /etc/ImageMagick-6/policy.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policymap [
  <!ELEMENT policymap (policy)*>
  <!ELEMENT policy (#PCDATA)>
  <!ATTLIST policy domain CDATA #REQUIRED>
  <!ATTLIST policy name CDATA #REQUIRED>
  <!ATTLIST policy pattern CDATA #IMPLIED>
  <!ATTLIST policy rights CDATA #REQUIRED>
]>
<policymap>
  <policy domain="coder" rights="none" pattern="MVG" />
  <policy domain="coder" rights="none" pattern="MSL" />
  <policy domain="coder" rights="none" pattern="TEXT" />
  <policy domain="coder" rights="none" pattern="SHOW" />
  <policy domain="coder" rights="none" pattern="WIN" />
  <policy domain="coder" rights="none" pattern="PLT" />
  <policy domain="coder" rights="none" pattern="EPHEMERAL" />
  <policy domain="coder" rights="none" pattern="URL" />
  <policy domain="coder" rights="none" pattern="HTTPS" />
  <policy domain="coder" rights="none" pattern="HTTP" />
  <policy domain="coder" rights="none" pattern="FTP" />
  <policy domain="resource" name="memory" value="256MiB"/>
  <policy domain="resource" name="map" value="512MiB"/>
  <policy domain="resource" name="width" value="16KP"/>
  <policy domain="resource" name="height" value="16KP"/>
  <policy domain="resource" name="area" value="128MP"/>
  <policy domain="resource" name="disk" value="1GiB"/>
</policymap>
POLICY
# NOTE: The above policy is correctly restrictive in the Docker image.
# However, the application config (print_shop.conf) sets an empty policy_file path,
# so the application's convert commands may bypass this policy at runtime.

# Copy from builder
COPY --from=builder /app /app
COPY --from=builder /usr/local/lib/perl5 /usr/local/lib/perl5

# Create data directories
RUN mkdir -p /var/data/artwork/uploads \
             /var/data/artwork/processed \
             /var/data/backups \
             /tmp/artwork_processing

# Set permissions
RUN chmod -R 777 /var/data /tmp/artwork_processing

# Environment
ENV MOJO_MODE=production
ENV PRINT_SHOP_DEBUG=1
ENV MOJO_LOG_LEVEL=debug
ENV PERL5OPT=-w

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000

# Start application
CMD ["morbo", "-l", "http://*:3000", "script/print_shop"]
