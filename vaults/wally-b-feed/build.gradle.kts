import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.springframework.boot") version "3.2.0"
    id("io.spring.dependency-management") version "1.1.4"
    kotlin("jvm") version "1.9.21"
    kotlin("plugin.spring") version "1.9.21"
    kotlin("plugin.serialization") version "1.9.21"
}

group = "com.wallyb"
version = "1.0.0"
java.sourceCompatibility = JavaVersion.VERSION_17

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-data-r2dbc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")

    // BUG-0001: Using outdated vulnerable commons-text with known RCE via StringSubstitutor (CWE-1395, CVSS 9.8, CRITICAL, Tier 1)
    implementation("org.apache.commons:commons-text:1.9")

    // BUG-0002: Using SnakeYAML without SafeConstructor enables arbitrary deserialization (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    implementation("org.yaml:snakeyaml:1.33")

    // BUG-0003: Outdated Postgres driver with known CVEs (CWE-1395, CVSS 5.3, MEDIUM, Tier 3)
    runtimeOnly("org.postgresql:r2dbc-postgresql:1.0.1.RELEASE")
    runtimeOnly("org.postgresql:postgresql:42.5.0")

    implementation("org.bouncycastle:bcprov-jdk18on:1.72")

    implementation("io.jsonwebtoken:jjwt-api:0.12.3")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.3")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.3")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.projectreactor:reactor-test")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs += "-Xjsr305=strict"
        jvmTarget = "17"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
