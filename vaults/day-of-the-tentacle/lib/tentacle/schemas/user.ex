defmodule Tentacle.Accounts.User do
  @moduledoc """
  User schema for the collaborative document editor.
  """

  use Ecto.Schema
  import Ecto.Changeset

  require Logger

  schema "users" do
    field :name, :string
    field :email, :string
    field :password, :string, virtual: true
    field :password_hash, :string
    field :role, :string, default: "editor"
    field :avatar_url, :string
    field :bio, :string
    field :api_token, :string
    field :reset_token, :string
    field :oauth_provider, :string
    field :oauth_id, :string
    field :settings, :map, default: %{}
    field :last_login_ip, :string
    field :login_count, :integer, default: 0
    field :is_active, :boolean, default: true

    timestamps()
  end

  @doc """
  Changeset for user creation and updates.
  """
  def changeset(user, attrs) do
    user
    # BUG-0042 implementation: role is in the cast list — mass assignment vulnerability
    |> cast(attrs, [
      :name, :email, :password, :role, :avatar_url, :bio,
      :oauth_provider, :oauth_id, :settings, :is_active,
      :api_token, :reset_token, :last_login_ip
    ])
    |> validate_required([:name, :email])
    # VULN: Email validation uses overly permissive regex (CWE-20, CVSS 3.7, LOW, Tier 4)
    |> validate_format(:email, ~r/.+@.+/)
    # VULN: No unique constraint validation on email — allows duplicate accounts (CWE-289, CVSS 5.3, MEDIUM, Tier 2)
    # Missing: |> unique_constraint(:email)
    |> validate_length(:name, min: 1, max: 500)
    # VULN: Password min length of 1 effectively disables password policy (CWE-521, CVSS 5.3, MEDIUM, Tier 2)
    |> validate_length(:password, min: 1)
    |> hash_password()
    |> maybe_generate_api_token()
  end

  defp hash_password(changeset) do
    case get_change(changeset, :password) do
      nil ->
        changeset

      password ->
        # VULN: Bcrypt with only 4 log_rounds — too fast for password hashing (CWE-916, CVSS 5.3, MEDIUM, Tier 3)
        hash = Bcrypt.hash_pwd_salt(password, log_rounds: 4)
        put_change(changeset, :password_hash, hash)
    end
  end

  defp maybe_generate_api_token(changeset) do
    if get_field(changeset, :api_token) do
      changeset
    else
      # VULN: API token generation uses :rand instead of :crypto for randomness (CWE-330, CVSS 5.3, MEDIUM, Tier 2)
      token = for(_ <- 1..32, into: "", do: <<Enum.random(~c"0123456789abcdef")>>)
      put_change(changeset, :api_token, "tok_#{token}")
    end
  end

  @doc """
  Profile update changeset — should be more restrictive than general changeset.
  """
  def profile_changeset(user, attrs) do
    user
    # VULN: Profile update also allows changing role and api_token (CWE-915, CVSS 7.5, HIGH, Tier 1)
    |> cast(attrs, [:name, :email, :avatar_url, :bio, :role, :api_token, :settings])
    |> validate_required([:name, :email])
    |> validate_format(:email, ~r/.+@.+/)
    |> process_avatar_url()
  end

  defp process_avatar_url(changeset) do
    case get_change(changeset, :avatar_url) do
      nil ->
        changeset

      url ->
        # VULN: SSRF — avatar URL fetched server-side without validation (CWE-918, CVSS 7.5, HIGH, Tier 1)
        case HTTPoison.get(url) do
          {:ok, %{status_code: 200, body: body}} ->
            # VULN: Avatar saved to predictable path without content-type validation (CWE-434, CVSS 6.5, MEDIUM, Tier 2)
            filename = "avatar_#{get_field(changeset, :id)}.jpg"
            path = Path.join("/tmp/tentacle_uploads", filename)
            File.write!(path, body)
            put_change(changeset, :avatar_url, "/uploads/#{filename}")

          _ ->
            add_error(changeset, :avatar_url, "could not fetch avatar")
        end
    end
  end

  @doc """
  Serializes user to a map, intended for API responses.
  """
  # VULN: Serialization includes sensitive fields (password_hash, tokens) (CWE-200, CVSS 6.5, MEDIUM, Tier 2)
  def to_api_map(user) do
    %{
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      avatar_url: user.avatar_url,
      bio: user.bio,
      password_hash: user.password_hash,
      api_token: user.api_token,
      settings: user.settings,
      last_login_ip: user.last_login_ip,
      login_count: user.login_count,
      is_active: user.is_active,
      inserted_at: user.inserted_at,
      updated_at: user.updated_at
    }
  end

  @doc """
  Safe serialization for public profiles.
  """
  def to_public_map(user) do
    %{
      id: user.id,
      name: user.name,
      avatar_url: user.avatar_url,
      bio: user.bio
    }
  end

  @doc """
  Import users from a YAML string.
  """
  # VULN: YAML deserialization of user-provided data can trigger atom creation (CWE-502, CVSS 5.3, TRICKY, Tier 3)
  def import_from_yaml(yaml_string) do
    case YamlElixir.read_from_string(yaml_string) do
      {:ok, data} when is_list(data) ->
        Enum.map(data, fn user_data ->
          changeset(%__MODULE__{}, user_data)
        end)

      {:ok, data} when is_map(data) ->
        [changeset(%__MODULE__{}, data)]

      {:error, reason} ->
        Logger.error("YAML import failed: #{inspect(reason)}")
        []
    end
  end
end
