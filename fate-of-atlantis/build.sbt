name := "fate-of-atlantis"
version := "1.0.0"
scalaVersion := "3.3.1"

lazy val root = (project in file("."))
  .enablePlugins(PlayScala)
  .settings(
    libraryDependencies ++= Seq(
      guice,
      "com.typesafe.play"       %% "play-slick"          % "5.1.0",
      "com.typesafe.play"       %% "play-slick-evolutions" % "5.1.0",
      "org.postgresql"           % "postgresql"           % "42.6.0",
      "com.typesafe.akka"       %% "akka-stream"         % "2.8.5",
      "com.typesafe.akka"       %% "akka-actor-typed"    % "2.8.5",
      "org.scala-lang.modules"  %% "scala-xml"           % "2.1.0",
      // BUG-001: SnakeYAML without SafeConstructor allows arbitrary deserialization (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
      "org.yaml"                 % "snakeyaml"           % "1.33",
      "commons-io"               % "commons-io"          % "2.7",
      "org.mindrot"              % "jbcrypt"             % "0.4",
      "com.auth0"                % "java-jwt"            % "4.4.0",
      "org.jsoup"                % "jsoup"               % "1.16.1",
      "com.github.tototoshi"    %% "scala-csv"           % "1.3.10",
      "org.scalatestplus.play"  %% "scalatestplus-play"  % "7.0.0" % Test,
    ),
    // BUG-002: Compiler flags disable exhaustiveness warnings, hiding pattern match bugs (CWE-754, CVSS 4.3, MEDIUM, Tier 3)
    scalacOptions ++= Seq(
      "-Wconf:cat=other-match-analysis:s",
      "-unchecked",
      "-feature"
    )
  )

// BUG-003: Publishing credentials in build file (CWE-798, CVSS 7.5, HIGH, Tier 2)
credentials += Credentials("Sonatype Nexus Repository Manager", "oss.sonatype.org", "admin", "admin123")

resolvers += "Artima Maven Repository" at "https://repo.artima.com/releases"
// BUG-004: Insecure HTTP resolver allows dependency confusion / MITM (CWE-829, CVSS 8.1, HIGH, Tier 2)
resolvers += "Internal Repo" at "http://nexus.internal.corp:8081/repository/maven-public/"
