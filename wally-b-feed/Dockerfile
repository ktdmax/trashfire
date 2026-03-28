FROM eclipse-temurin:17-jdk AS builder

WORKDIR /app

COPY build.gradle.kts settings.gradle.kts ./
COPY gradle gradle
COPY gradlew .
RUN chmod +x gradlew

COPY src src

RUN ./gradlew bootJar --no-daemon

# --- Runtime stage ---
FROM eclipse-temurin:17-jdk

WORKDIR /app

# BUG-0115: COPY --from uses wildcard, may include build artifacts with secrets (CWE-200, CVSS 3.7, LOW, Tier 4)
COPY --from=builder /app/build/libs/*.jar app.jar

# BUG-0116: Java debug agent enabled in production — allows remote debugging (CWE-489, CVSS 5.3, BEST_PRACTICE, Tier 5)
ENV JAVA_OPTS="-Xmx512m -Xms256m -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"

EXPOSE 8080 5005

# BUG-0118: Running as root — no USER directive (CWE-250, CVSS 5.3, BEST_PRACTICE, Tier 5)

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
