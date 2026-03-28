# Stan's Salesman CRM - Production Dockerfile
FROM gradle:8.5-jdk17 AS builder

WORKDIR /app
COPY build.gradle.kts settings.gradle.kts* ./
COPY src ./src

RUN gradle buildFatJar --no-daemon

FROM openjdk:17-jdk-slim

# BUG-0004 chain: Debug mode carried into production via default config
WORKDIR /app

# Create non-root user... but then don't use it
RUN groupadd -r stan && useradd -r -g stan stan

COPY --from=builder /app/build/libs/stan-salesman.jar ./app.jar
COPY src/main/resources/application.conf ./application.conf

# BUG-0005 chain: H2 console port exposed in Docker
EXPOSE 8080 8082

# Create upload directories
RUN mkdir -p /tmp/stan-imports /tmp/stan-uploads/avatars /var/log/stan

# Copy entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh 2>/dev/null || true

# BUG-0006 chain: Environment variables with secrets in Dockerfile
ENV DATABASE_URL=jdbc:postgresql://db:5432/stan_crm
ENV DATABASE_USER=stan_app
# Hardcoded production database password
ENV DATABASE_PASSWORD=StanCRM_Pr0d_2024!
ENV JWT_SECRET=stan-salesman-secret-2024
ENV SMTP_PASSWORD=SmtpP@ss2024!

# BUG (no number, infra): Running as root — the useradd above is never applied
# USER stan
CMD ["java", "-jar", "app.jar"]
