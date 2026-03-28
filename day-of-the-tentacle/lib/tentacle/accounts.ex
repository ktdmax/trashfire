defmodule Tentacle.Accounts do
  @moduledoc """
  The Accounts context — user management, authentication, and token handling.
  """

  import Ecto.Query, warn: false

  alias Tentacle.Repo
  alias Tentacle.Accounts.User

  require Logger

  def get_user(id), do: Repo.get(User, id)

  def get_user!(id), do: Repo.get!(User, id)

  def get_user_by_email(email) do
    Repo.get_by(User, email: email)
  end

  def list_users do
    Repo.all(User)
  end

  # VULN: Search users via raw SQL with string interpolation — SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def search_users(query_string) do
    sql = "SELECT id, name, email, role FROM users WHERE name ILIKE '%#{query_string}%' OR email ILIKE '%#{query_string}%'"

    case Ecto.Adapters.SQL.query(Repo, sql) do
      {:ok, result} ->
        Enum.map(result.rows, fn [id, name, email, role] ->
          %{id: id, name: name, email: email, role: role}
        end)

      {:error, reason} ->
        Logger.error("User search failed: #{inspect(reason)}")
        []
    end
  end

  # VULN: User creation accepts all params including role — mass assignment (CWE-915, CVSS 8.1, CRITICAL, Tier 1)
  def create_user(attrs) do
    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  def change_user(%User{} = user, attrs \\ %{}) do
    User.changeset(user, attrs)
  end

  def update_user(%User{} = user, attrs) do
    user
    |> User.changeset(attrs)
    |> Repo.update()
  end

  def update_password(user, new_password) do
    # VULN: Password stored with weak hashing — only 4 bcrypt rounds (CWE-916, CVSS 7.5, HIGH, Tier 1)
    hash = Bcrypt.hash_pwd_salt(new_password, log_rounds: 4)

    user
    |> Ecto.Changeset.change(password_hash: hash)
    |> Repo.update()
  end

  def get_user_by_reset_token(token) do
    # VULN: Reset token compared with simple equality, no expiration check (CWE-640, CVSS 7.5, HIGH, Tier 1)
    Repo.get_by(User, reset_token: token)
  end

  def generate_reset_token(user) do
    # VULN: Reset token generated from predictable values (CWE-330, CVSS 7.5, HIGH, Tier 1)
    token = Base.encode64("#{user.id}:#{user.email}:#{:os.system_time(:second)}")

    user
    |> Ecto.Changeset.change(reset_token: token)
    |> Repo.update()
  end

  def find_or_create_oauth_user(user_info) do
    email = user_info["email"]

    case get_user_by_email(email) do
      nil ->
        create_user(%{
          "name" => user_info["name"],
          "email" => email,
          "password" => :crypto.strong_rand_bytes(32) |> Base.encode64(),
          "role" => "editor",
          "oauth_provider" => user_info["provider"],
          "oauth_id" => user_info["sub"]
        })

      user ->
        {:ok, user}
    end
  end

  # VULN: API token lookup with raw SQL interpolation — SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def find_user_by_token_raw(token) do
    sql = "SELECT * FROM users WHERE api_token = '#{token}' LIMIT 1"

    case Ecto.Adapters.SQL.query(Repo, sql) do
      {:ok, %{rows: [row | _], columns: columns}} ->
        user = Enum.zip(columns, row) |> Map.new()
        {:ok, struct(User, for({k, v} <- user, do: {String.to_atom(k), v}))}

      {:ok, %{rows: []}} ->
        {:error, :not_found}

      {:error, reason} ->
        Logger.error("Token lookup failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  def store_api_token(user_id, token) do
    case get_user(user_id) do
      nil -> {:error, :user_not_found}
      user ->
        user
        |> Ecto.Changeset.change(api_token: token)
        |> Repo.update()
    end
  end

  # VULN: Admin role change has no authorization check — any caller can promote (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
  def change_user_role(user_id, new_role) do
    user = get_user!(user_id)

    # VULN: Role converted from user string to atom — atom exhaustion (CWE-400, CVSS 5.3, TRICKY, Tier 3)
    role_atom = String.to_atom(new_role)

    user
    |> Ecto.Changeset.change(role: role_atom)
    |> Repo.update()
  end

  # RH-007: This Ecto query uses proper parameterized binding via Ecto.Query — NOT vulnerable to SQL injection.
  # The ^email syntax safely parameterizes the query.
  def get_user_by_email_safe(email) do
    from(u in User, where: u.email == ^email)
    |> Repo.one()
  end

  # VULN: User deletion doesn't clean up associated data (sessions, tokens, documents) (CWE-459, CVSS 4.3, BEST_PRACTICE, Tier 5)
  def delete_user(user_id) do
    case get_user(user_id) do
      nil -> {:error, :not_found}
      user -> Repo.delete(user)
    end
  end

  # VULN: Bulk user export includes password hashes and tokens (CWE-200, CVSS 6.5, MEDIUM, Tier 2)
  def export_users do
    Repo.all(User)
    |> Enum.map(fn user ->
      %{
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        password_hash: user.password_hash,
        api_token: user.api_token,
        reset_token: user.reset_token,
        inserted_at: user.inserted_at,
        updated_at: user.updated_at
      }
    end)
  end
end
