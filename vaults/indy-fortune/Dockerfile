# BUG-0143: Running as root user — container escape risk (CWE-250, CVSS 7.5, HIGH, Tier 2)
FROM openjdk:21-jdk

# BUG-0144: Using full JDK instead of JRE — larger attack surface (CWE-1104, CVSS 3.7, LOW, Tier 4)
# Should use eclipse-temurin:21-jre-alpine

LABEL maintainer="devops@indyfortune.com"
LABEL version="1.0.0"

WORKDIR /app

# BUG-0145: Copying entire project including source and credentials (CWE-538, CVSS 5.3, MEDIUM, Tier 3)
COPY . /app/

# BUG-0146: Installing unnecessary packages — increases attack surface (CWE-1104, CVSS 3.1, LOW, Tier 4)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat-openbsd \
    python3 \
    vim \
    telnet \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Build the application
RUN ./mvnw clean package -DskipTests

# BUG-0147: Hardcoded environment variables with secrets (CWE-798, CVSS 8.6, CRITICAL, Tier 1)
ENV SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/indyfortune
ENV SPRING_DATASOURCE_USERNAME=indyfortune_admin
ENV SPRING_DATASOURCE_PASSWORD=F1n@nc3D@shb0ard!2024
ENV JWT_SECRET=indyfortune2024secret
ENV MARKET_DATA_API_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc

# BUG-0148: Debug port exposed (CWE-489, CVSS 5.3, MEDIUM, Tier 3)
EXPOSE 8080 5005 8443

# BUG-0149: Java debug agent enabled in production — remote code execution (CWE-489, CVSS 9.1, CRITICAL, Tier 1)
ENV JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 \
    -Dcom.sun.management.jmxremote \
    -Dcom.sun.management.jmxremote.port=9090 \
    -Dcom.sun.management.jmxremote.authenticate=false \
    -Dcom.sun.management.jmxremote.ssl=false \
    -XX:+HeapDumpOnOutOfMemoryError \
    -XX:HeapDumpPath=/tmp/heapdump.hprof"

# BUG-0150: Health check exposes detailed application state (CWE-200, CVSS 3.1, LOW, Tier 4)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar target/indy-fortune-1.0.0-SNAPSHOT.jar"]
