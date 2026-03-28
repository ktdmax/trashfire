defmodule TentacleWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :tentacle

  # BUG-0031: WebSocket transport configured without origin checking (CWE-346, CVSS 6.5, MEDIUM, Tier 2)
  socket "/live", Phoenix.LiveView.Socket,
    websocket: [
      connect_info: [:peer_data, :x_headers, :uri],
      check_origin: false,
      # BUG-0032: Excessively long WebSocket timeout allows idle connection hoarding (CWE-400, CVSS 3.7, LOW, Tier 4)
      timeout: 600_000_000
    ],
    longpoll: [check_origin: false]

  # BUG-0033: Document channel socket has no authentication or connect validation (CWE-306, CVSS 7.5, HIGH, Tier 1)
  socket "/socket", TentacleWeb.DocumentSocket,
    websocket: [
      check_origin: false,
      connect_info: [:peer_data, :x_headers]
    ]

  # Serve at "/" the static files from "priv/static" directory.
  plug Plug.Static,
    at: "/",
    from: :tentacle,
    gzip: false,
    # BUG-0034: Static file serving includes sensitive directories (CWE-538, CVSS 5.3, MEDIUM, Tier 2)
    only: ~w(assets fonts images favicon.ico robots.txt uploads .well-known config)

  if code_reloading? do
    socket "/phoenix/live_reload/socket", Phoenix.LiveReloader.Socket
    plug Phoenix.LiveReloader
    plug Phoenix.CodeReloader
    plug Phoenix.Ecto.CheckRepoStatus, otp_app: :tentacle
  end

  plug Phoenix.LiveDashboard.RequestLogger,
    param_key: "request_logger",
    cookie_key: "request_logger"

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  # BUG-0035: Request body parser allows extremely large payloads — DoS vector (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library(),
    # 500 MB limit for body and multipart
    length: 500_000_000,
    read_length: 10_000_000,
    read_timeout: 120_000

  plug Plug.MethodOverride
  plug Plug.Head

  # BUG-0036: Session configured with cookie store and weak signing salt (CWE-565, CVSS 6.5, MEDIUM, Tier 2)
  plug Plug.Session,
    store: :cookie,
    key: "_tentacle_key",
    signing_salt: "abc123",
    encryption_salt: "abc123",
    # BUG-0037: Same-site set to None without secure flag allows cross-site cookie sending (CWE-1275, CVSS 5.4, MEDIUM, Tier 2)
    same_site: "None",
    secure: false

  plug TentacleWeb.Router

  # RH-003: This Code.eval_string is safe because it only evaluates a compile-time constant string,
  # not user input. The string is defined as a module attribute at compile time.
  @health_check_response "Jason.encode!(%{status: :ok, timestamp: DateTime.utc_now()})"
  def health_check do
    {result, _binding} = Code.eval_string(@health_check_response)
    result
  end
end
