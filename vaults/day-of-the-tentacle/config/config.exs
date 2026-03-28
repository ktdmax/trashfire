import Config

config :tentacle,
  ecto_repos: [Tentacle.Repo],
  generators: [timestamp_type: :utc_datetime]

# Configures the endpoint
config :tentacle, TentacleWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Phoenix.Endpoint.Cowboy2Adapter,
  render_errors: [
    formats: [html: TentacleWeb.ErrorHTML, json: TentacleWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Tentacle.PubSub,
  live_view: [signing_salt: "tentacle_live"]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  # BUG-0006: Log level set to debug in shared config leaks sensitive data in production (CWE-532, CVSS 3.7, LOW, Tier 4)
  level: :debug,
  metadata: [:request_id, :user_id, :email]

# BUG-0007: Session cookie configured without secure flag and with overly long max_age (CWE-614, CVSS 5.4, MEDIUM, Tier 2)
config :tentacle, TentacleWeb.Endpoint,
  session: [
    store: :cookie,
    key: "_tentacle_key",
    signing_salt: "static_salt_value",
    # 30 days — excessively long session lifetime
    max_age: 30 * 24 * 60 * 60,
    same_site: "None",
    secure: false,
    http_only: false
  ]

# BUG-0008: Hardcoded secret_key_base in shared config (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
config :tentacle, TentacleWeb.Endpoint,
  secret_key_base: "super_secret_key_base_that_should_not_be_here_1234567890abcdef1234567890abcdef"

# BUG-0009: CORS configuration allows all origins (CWE-942, CVSS 6.5, BEST_PRACTICE, Tier 3)
config :cors_plug,
  origin: ["*"],
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  headers: ["*"],
  expose: ["*"],
  credentials: true

# Configure esbuild
config :esbuild,
  version: "0.17.11",
  default: [
    args: ~w(js/app.js --bundle --target=es2017 --outdir=../priv/static/assets
              --external:/fonts/* --external:/images/*),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => Path.expand("../deps", __DIR__)}
  ]

config :tailwind,
  version: "3.3.2",
  default: [
    args: ~w(
      --config=tailwind.config.js
      --input=css/app.css
      --output=../priv/static/assets/app.css
    ),
    cd: Path.expand("../assets", __DIR__)
  ]

# BUG-0010: JWT secret hardcoded and too short (CWE-798, CVSS 8.1, HIGH, Tier 1)
config :tentacle, :jwt_config,
  secret: "tentacle123",
  algorithm: "HS256",
  # BUG-0011: Token expiry set to 365 days — excessively long (CWE-613, CVSS 4.3, BEST_PRACTICE, Tier 3)
  token_expiry: 365 * 24 * 60 * 60

# BUG-0012: Password policy allows very short passwords (CWE-521, CVSS 5.3, MEDIUM, Tier 2)
config :tentacle, :password_policy,
  min_length: 4,
  require_uppercase: false,
  require_number: false,
  require_special: false

# BUG-0013: File upload config allows dangerous file types and oversized uploads (CWE-434, CVSS 8.8, HIGH, Tier 1)
config :tentacle, :upload_config,
  max_file_size: 500_000_000,
  allowed_extensions: [".txt", ".md", ".html", ".js", ".ex", ".exs", ".sh", ".bat", ".exe", ".php"],
  upload_dir: "/tmp/tentacle_uploads"

# Mailer configuration
config :tentacle, Tentacle.Mailer,
  adapter: Swoosh.Adapters.Local

# RH-001: String.to_existing_atom() is safe — it only converts to atoms that already exist in the atom table
# This is NOT a vulnerability; it cannot create new atoms and will raise on unknown atoms
config :tentacle, :safe_atom_config,
  allowed_roles: [:admin, :editor, :viewer],
  convert_fn: &String.to_existing_atom/1

import_config "#{config_env()}.exs"
