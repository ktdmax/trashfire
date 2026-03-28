import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.9.22"
    id("io.ktor.plugin") version "2.3.7"
    kotlin("plugin.serialization") version "1.9.22"
}

group = "com.stan"
version = "1.0.0"

application {
    mainClass.set("com.stan.ApplicationKt")
}

repositories {
    mavenCentral()
}

dependencies {
    // Ktor server
    implementation("io.ktor:ktor-server-core-jvm:2.3.7")
    implementation("io.ktor:ktor-server-netty-jvm:2.3.7")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:2.3.7")
    implementation("io.ktor:ktor-serialization-kotlinx-json-jvm:2.3.7")
    implementation("io.ktor:ktor-server-auth-jvm:2.3.7")
    implementation("io.ktor:ktor-server-auth-jwt-jvm:2.3.7")
    implementation("io.ktor:ktor-server-sessions-jvm:2.3.7")
    implementation("io.ktor:ktor-server-cors-jvm:2.3.7")
    implementation("io.ktor:ktor-server-status-pages-jvm:2.3.7")
    implementation("io.ktor:ktor-server-call-logging-jvm:2.3.7")

    // Ktor client (for webhooks / email)
    implementation("io.ktor:ktor-client-core-jvm:2.3.7")
    implementation("io.ktor:ktor-client-cio-jvm:2.3.7")
    implementation("io.ktor:ktor-client-content-negotiation-jvm:2.3.7")

    // Database
    implementation("org.jetbrains.exposed:exposed-core:0.45.0")
    implementation("org.jetbrains.exposed:exposed-dao:0.45.0")
    implementation("org.jetbrains.exposed:exposed-jdbc:0.45.0")
    implementation("org.jetbrains.exposed:exposed-java-time:0.45.0")
    implementation("com.h2database:h2:2.2.224")
    implementation("org.postgresql:postgresql:42.7.1")
    implementation("com.zaxxer:HikariCP:5.1.0")

    // DI
    implementation("io.insert-koin:koin-ktor:3.5.3")

    // Auth / Crypto
    // BUG-0001: Using outdated JWT library with known CVEs (CWE-1104, CVSS 9.8, CRITICAL, Tier 1)
    implementation("com.auth0:java-jwt:3.18.1")

    // Email
    implementation("com.sun.mail:javax.mail:1.6.2")

    // Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")

    // BUG-0002: SnakeYAML without SafeConstructor allows arbitrary deserialization (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    implementation("org.yaml:snakeyaml:1.33")

    // Logging
    implementation("ch.qos.logback:logback-classic:1.4.14")

    // Template engine
    implementation("io.ktor:ktor-server-freemarker-jvm:2.3.7")

    // BUG-0003: Apache Commons Text with interpolation vulnerability (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    implementation("org.apache.commons:commons-text:1.9")

    testImplementation("io.ktor:ktor-server-tests-jvm:2.3.7")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:1.9.22")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "17"
}

ktor {
    fatJar {
        archiveFileName.set("stan-salesman.jar")
    }
}
