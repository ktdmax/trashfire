import Config

if System.get_env("PHX_SERVER") do
  config :tentacle, TentacleWeb.Endpoint, server: true
end

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :tentacle, Tentacle.Repo,
    # BUG-0014: SSL disabled for database connection in production (CWE-319, CVSS 7.5, HIGH, Tier 1)
    ssl: false,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    socket_options: maybe_ipv6,
    # BUG-0015: Statement timeout disabled, allows long-running queries to DoS the database (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 3)
    timeout: :infinity,
    # BUG-0016: Queue target set excessively high (CWE-400, CVSS 3.7, LOW, Tier 4)
    queue_target: 60_000,
    queue_interval: 60_000

  # BUG-0017: secret_key_base falls back to a hardcoded default if env var is missing (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      "fallback_secret_key_base_do_not_use_in_production_but_we_do_anyway_1234567890"

  host = System.get_env("PHX_HOST") || "example.com"
  port = String.to_integer(System.get_env("PORT") || "4000")

  config :tentacle, TentacleWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      ip: {0, 0, 0, 0, 0, 0, 0, 0},
      port: port,
      # BUG-0018: Transport options allow unlimited connections and oversized headers (CWE-400, CVSS 5.3, TRICKY, Tier 3)
      transport_options: [
        max_connections: :infinity,
        max_header_value_length: 1_048_576
      ]
    ],
    secret_key_base: secret_key_base

  # BUG-0019: Admin credentials loaded from env but with insecure defaults (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
  config :tentacle, :admin_config,
    admin_email: System.get_env("ADMIN_EMAIL") || "admin@tentacle.local",
    admin_password: System.get_env("ADMIN_PASSWORD") || "admin123",
    admin_api_key: System.get_env("ADMIN_API_KEY") || "sk-tentacle-admin-key-default"

  # BUG-0020: Redis connection without authentication or TLS (CWE-319, CVSS 6.5, MEDIUM, Tier 2)
  config :tentacle, :redis,
    host: System.get_env("REDIS_HOST") || "localhost",
    port: String.to_integer(System.get_env("REDIS_PORT") || "6379"),
    password: nil,
    ssl: false,
    database: 0

  # BUG-0021: External service URL taken from environment without validation (CWE-918, CVSS 7.5, HIGH, Tier 1)
  config :tentacle, :external_services,
    webhook_url: System.get_env("WEBHOOK_URL"),
    callback_url: System.get_env("CALLBACK_URL"),
    avatar_proxy_url: System.get_env("AVATAR_PROXY_URL") || "http://localhost:3000/proxy"

  # RH-002: This Ecto fragment uses proper parameterized binding ($1) — NOT vulnerable to SQL injection
  # The interpolation here is a compile-time module attribute, not user input
  config :tentacle, :search_config,
    default_query: "SELECT id, title FROM documents WHERE workspace_id = $1 ORDER BY updated_at DESC"
end
