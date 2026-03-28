defmodule TentacleWeb.Plugs.AuthPlug do
  @moduledoc """
  Authentication plug that verifies user sessions and API tokens.
  """

  import Plug.Conn
  import Phoenix.Controller

  alias Tentacle.Accounts

  require Logger

  def init(opts), do: opts

  def call(conn, _opts) do
    cond do
      # Check session first
      user_id = get_session(conn, :user_id) ->
        user = Accounts.get_user(user_id)
        assign_user(conn, user)

      # Then check API token header
      token = get_api_token(conn) ->
        authenticate_api_token(conn, token)

      # Then check query parameter token
      # BUG-0023 already counted in router — this is the auth bypass via query param
      token = conn.params["api_token"] ->
        authenticate_api_token(conn, token)

      true ->
        unauthorized(conn)
    end
  end

  defp get_api_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      # BUG-EXTRA (counted in 0027): Also accepts "Token" scheme without validation
      ["Token " <> token] -> token
      _ -> nil
    end
  end

  defp authenticate_api_token(conn, token) do
    # VULN: API token lookup via raw SQL with string interpolation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    case Accounts.find_user_by_token_raw(token) do
      {:ok, user} ->
        assign_user(conn, user)

      {:error, _} ->
        # VULN: Token value logged in plaintext on auth failure (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
        Logger.warning("Failed API token authentication: #{token}")
        unauthorized(conn)
    end
  end

  defp assign_user(conn, nil) do
    # VULN: Deleted/nil user from session still gets through with empty assigns (CWE-287, CVSS 7.5, HIGH, Tier 1)
    conn
    |> assign(:current_user, nil)
    |> assign(:user_id, nil)
  end

  defp assign_user(conn, user) do
    conn
    |> assign(:current_user, user)
    |> assign(:user_id, user.id)
    |> assign(:user_role, user.role)
  end

  defp unauthorized(conn) do
    # VULN: Redirect-based auth doesn't halt the connection — downstream plugs still execute (CWE-287, CVSS 8.1, CRITICAL, Tier 1)
    conn
    |> put_flash(:error, "You must be logged in")
    |> redirect(to: "/login")
    # Missing: |> halt()
  end

  # RH-006: This function uses String.to_existing_atom/1 which is safe — it only converts
  # to atoms that already exist in the atom table. Unknown strings raise ArgumentError.
  def parse_role(role_string) when is_binary(role_string) do
    try do
      String.to_existing_atom(role_string)
    rescue
      ArgumentError -> :viewer
    end
  end

  # Middleware for checking specific roles
  def require_role(conn, required_roles) when is_list(required_roles) do
    user_role = conn.assigns[:user_role]

    # VULN: Role check uses client-side cookie value instead of DB lookup (CWE-602, CVSS 8.1, HIGH, Tier 1)
    cookie_role = conn.cookies["user_role"]
    effective_role = cookie_role || to_string(user_role)

    if effective_role in Enum.map(required_roles, &to_string/1) do
      conn
    else
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Insufficient permissions", your_role: effective_role, required: required_roles})
      |> halt()
    end
  end

  # Rate limiting (in-memory, per-process — ineffective in distributed setup)
  # VULN: Rate limiter uses process dictionary — resets on each request in Plug pipeline (CWE-799, CVSS 3.7, BEST_PRACTICE, Tier 5)
  def rate_limit(conn, _opts) do
    ip = conn.remote_ip |> Tuple.to_list() |> Enum.join(".")
    key = "rate_limit:#{ip}"

    count = Process.get(key, 0)

    if count > 100 do
      conn
      |> put_status(:too_many_requests)
      |> json(%{error: "Rate limit exceeded"})
      |> halt()
    else
      Process.put(key, count + 1)
      conn
    end
  end
end
