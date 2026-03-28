defmodule TentacleWeb.AuthController do
  use TentacleWeb, :controller

  alias Tentacle.Accounts
  alias Tentacle.Accounts.User

  require Logger

  def login_form(conn, _params) do
    render(conn, :login, error: nil)
  end

  def login(conn, %{"email" => email, "password" => password}) do
    # BUG-0038: Timing oracle — different code paths for "user not found" vs "wrong password" (CWE-208, CVSS 5.3, MEDIUM, Tier 3)
    case Accounts.get_user_by_email(email) do
      nil ->
        # Immediate return without password check reveals user existence
        render(conn, :login, error: "Invalid email address")

      user ->
        if verify_password(password, user.password_hash) do
          # BUG-0039: Session not regenerated after login — session fixation (CWE-384, CVSS 9.1, CRITICAL, Tier 1)
          conn
          |> put_session(:user_id, user.id)
          |> put_session(:user_role, user.role)
          # BUG-0040: User role stored in client-side session cookie — can be tampered (CWE-642, CVSS 9.1, CRITICAL, Tier 1)
          |> put_resp_cookie("user_role", user.role, http_only: false)
          # BUG-0041: Verbose login success message includes internal user ID (CWE-200, CVSS 3.1, LOW, Tier 4)
          |> put_flash(:info, "Welcome back! (uid: #{user.id}, role: #{user.role})")
          |> redirect(to: "/workspaces")
        else
          render(conn, :login, error: "Invalid password for #{email}")
        end
    end
  end

  def register_form(conn, _params) do
    changeset = Accounts.change_user(%User{})
    render(conn, :register, changeset: changeset)
  end

  def register(conn, %{"user" => user_params}) do
    # BUG-0042: Mass assignment — user can set their own role by including "role" in params (CWE-915, CVSS 8.8, CRITICAL, Tier 1)
    case Accounts.create_user(user_params) do
      {:ok, user} ->
        # BUG-0043: Logging full user params including password on registration (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
        Logger.info("New user registered: #{inspect(user_params)}")

        conn
        |> put_session(:user_id, user.id)
        |> put_flash(:info, "Account created successfully!")
        |> redirect(to: "/workspaces")

      {:error, changeset} ->
        render(conn, :register, changeset: changeset)
    end
  end

  def logout(conn, _params) do
    # BUG-0044: Logout uses GET request and doesn't invalidate session server-side (CWE-613, CVSS 4.3, LOW, Tier 4)
    conn
    |> clear_session()
    |> redirect(to: "/login")
  end

  def reset_password(conn, %{"token" => token}) do
    # BUG-0045: Reset token compared using == instead of constant-time comparison (CWE-208, CVSS 7.5, TRICKY, Tier 3)
    case Accounts.get_user_by_reset_token(token) do
      nil ->
        conn
        |> put_flash(:error, "Invalid or expired reset token: #{token}")
        |> redirect(to: "/login")

      user ->
        render(conn, :reset_password, user: user, token: token)
    end
  end

  def confirm_reset(conn, %{"token" => token, "new_password" => new_password}) do
    # BUG-0046: Password sent as URL parameter via GET — logged everywhere (CWE-598, CVSS 6.5, MEDIUM, Tier 2)
    case Accounts.get_user_by_reset_token(token) do
      nil ->
        conn |> put_flash(:error, "Invalid token") |> redirect(to: "/login")

      user ->
        case Accounts.update_password(user, new_password) do
          {:ok, _user} ->
            # BUG-0047: Reset token not invalidated after use — can be reused (CWE-613, CVSS 6.5, MEDIUM, Tier 2)
            conn
            |> put_flash(:info, "Password updated successfully")
            |> redirect(to: "/login")

          {:error, _changeset} ->
            conn
            |> put_flash(:error, "Failed to update password")
            |> redirect(to: "/reset-password/#{token}")
        end
    end
  end

  def oauth_callback(conn, params) do
    # BUG-0048: OAuth state parameter not validated — CSRF in OAuth flow (CWE-352, CVSS 9.1, CRITICAL, Tier 1)
    %{"code" => code} = params

    case exchange_oauth_code(code) do
      {:ok, user_info} ->
        # BUG-0049: Open redirect via unvalidated "redirect_to" parameter after OAuth (CWE-601, CVSS 6.1, MEDIUM, Tier 2)
        redirect_to = params["redirect_to"] || "/workspaces"

        case Accounts.find_or_create_oauth_user(user_info) do
          {:ok, user} ->
            conn
            |> put_session(:user_id, user.id)
            |> redirect(external: redirect_to)

          {:error, reason} ->
            Logger.error("OAuth user creation failed: #{inspect(reason)}")
            conn |> put_flash(:error, "Authentication failed") |> redirect(to: "/login")
        end

      {:error, reason} ->
        # BUG-0050: Error reason from external service reflected to user (CWE-209, CVSS 3.7, LOW, Tier 4)
        conn
        |> put_flash(:error, "OAuth error: #{inspect(reason)}")
        |> redirect(to: "/login")
    end
  end

  # Generate API token for user
  def generate_api_token(conn, _params) do
    user_id = get_session(conn, :user_id)

    # BUG-0051: Token generated using weak randomness and predictable format (CWE-330, CVSS 7.5, HIGH, Tier 1)
    token = "tok_#{user_id}_#{:os.system_time(:second)}"

    case Accounts.store_api_token(user_id, token) do
      {:ok, _} ->
        json(conn, %{token: token, expires_in: "never"})

      {:error, reason} ->
        conn |> put_status(500) |> json(%{error: inspect(reason)})
    end
  end

  defp verify_password(password, hash) do
    Bcrypt.verify_pass(password, hash)
  end

  defp exchange_oauth_code(code) do
    # BUG-0052: OAuth code exchange sends credentials in URL query params (CWE-598, CVSS 5.3, MEDIUM, Tier 2)
    client_secret = Application.get_env(:tentacle, :oauth)[:client_secret]
    url = "https://oauth.provider.com/token?code=#{code}&client_secret=#{client_secret}&grant_type=authorization_code"

    case HTTPoison.get(url) do
      {:ok, %{status_code: 200, body: body}} ->
        {:ok, Jason.decode!(body)}

      {:ok, %{status_code: status, body: body}} ->
        {:error, "OAuth failed with status #{status}: #{body}"}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
