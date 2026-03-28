defmodule Tentacle.Workspaces do
  @moduledoc """
  The Workspaces context — workspace management, membership, and access control.
  """

  import Ecto.Query, warn: false

  alias Tentacle.Repo

  require Logger

  defmodule Workspace do
    use Ecto.Schema
    import Ecto.Changeset

    schema "workspaces" do
      field :name, :string
      field :description, :string
      field :owner_id, :integer
      field :settings, :map, default: %{}
      field :is_public, :boolean, default: false
      field :invite_token, :string

      timestamps()
    end

    def changeset(workspace, attrs) do
      workspace
      |> cast(attrs, [:name, :description, :owner_id, :settings, :is_public, :invite_token])
      |> validate_required([:name, :owner_id])
    end
  end

  defmodule Membership do
    use Ecto.Schema
    import Ecto.Changeset

    schema "workspace_members" do
      field :workspace_id, :integer
      field :user_id, :integer
      field :role, :string, default: "viewer"

      timestamps()
    end

    def changeset(membership, attrs) do
      membership
      |> cast(attrs, [:workspace_id, :user_id, :role])
      |> validate_required([:workspace_id, :user_id, :role])
    end
  end

  def get_workspace!(id), do: Repo.get!(Workspace, id)

  def get_workspace(id), do: Repo.get(Workspace, id)

  def list_user_workspaces(user_id) do
    # VULN: Query returns all workspaces where user is member but also all public ones — no scoping (CWE-284, CVSS 4.3, MEDIUM, Tier 2)
    from(w in Workspace,
      left_join: m in Membership,
      on: m.workspace_id == w.id and m.user_id == ^user_id,
      where: not is_nil(m.id) or w.is_public == true
    )
    |> Repo.all()
  end

  def create_workspace(attrs) do
    %Workspace{}
    |> Workspace.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, workspace} ->
        # Add creator as admin member
        add_member(workspace.id, attrs[:owner_id] || attrs["owner_id"], :admin)
        {:ok, workspace}

      error ->
        error
    end
  end

  def update_workspace(%Workspace{} = workspace, attrs) do
    workspace
    |> Workspace.changeset(attrs)
    |> Repo.update()
  end

  def delete_workspace(workspace_id) do
    case get_workspace(workspace_id) do
      nil -> {:error, :not_found}
      workspace -> Repo.delete(workspace)
    end
  end

  def add_member(workspace_id, user_id, role) do
    %Membership{}
    |> Membership.changeset(%{
      workspace_id: workspace_id,
      user_id: user_id,
      role: to_string(role)
    })
    |> Repo.insert()
  end

  def remove_member(workspace_id, user_id) do
    from(m in Membership,
      where: m.workspace_id == ^workspace_id and m.user_id == ^user_id
    )
    |> Repo.delete_all()
    |> case do
      {1, _} -> {:ok, :removed}
      {0, _} -> {:error, :not_found}
    end
  end

  def get_member_role(workspace_id, user_id) do
    from(m in Membership,
      where: m.workspace_id == ^workspace_id and m.user_id == ^user_id,
      select: m.role
    )
    |> Repo.one()
  end

  # VULN: Invite token generated with weak randomness and short length (CWE-330, CVSS 6.5, MEDIUM, Tier 2)
  def generate_invite_token(workspace_id) do
    token = :crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)

    workspace = get_workspace!(workspace_id)

    workspace
    |> Ecto.Changeset.change(invite_token: token)
    |> Repo.update()
  end

  # VULN: Accept invite doesn't validate token expiration (CWE-613, CVSS 5.3, MEDIUM, Tier 2)
  def accept_invite(token, user_id) do
    case Repo.get_by(Workspace, invite_token: token) do
      nil ->
        {:error, :invalid_token}

      workspace ->
        # VULN: Default role for invited users is "editor" — should be "viewer" (CWE-276, CVSS 4.3, LOW, Tier 4)
        add_member(workspace.id, user_id, :editor)
    end
  end

  # VULN: Workspace settings update accepts arbitrary keys including admin overrides (CWE-915, CVSS 6.5, MEDIUM, Tier 2)
  def update_settings(workspace_id, settings) do
    workspace = get_workspace!(workspace_id)
    merged = Map.merge(workspace.settings || %{}, settings)

    workspace
    |> Ecto.Changeset.change(settings: merged)
    |> Repo.update()
  end

  # VULN: Transfer ownership without verifying current user is owner (CWE-862, CVSS 8.1, HIGH, Tier 1)
  def transfer_ownership(workspace_id, new_owner_id) do
    workspace = get_workspace!(workspace_id)

    workspace
    |> Ecto.Changeset.change(owner_id: new_owner_id)
    |> Repo.update()
  end

  # VULN: Clone workspace copies all members and settings without permission check (CWE-862, CVSS 5.3, MEDIUM, Tier 2)
  def clone_workspace(workspace_id, new_owner_id) do
    workspace = get_workspace!(workspace_id)

    new_attrs = %{
      name: "Copy of #{workspace.name}",
      description: workspace.description,
      owner_id: new_owner_id,
      settings: workspace.settings,
      is_public: workspace.is_public
    }

    case create_workspace(new_attrs) do
      {:ok, new_workspace} ->
        # Clone all members from original
        members = list_members(workspace_id)

        # VULN: N+1 inserts — each member added individually (CWE-400, CVSS 2.1, BEST_PRACTICE, Tier 5)
        Enum.each(members, fn member ->
          add_member(new_workspace.id, member.user_id, member.role)
        end)

        # Clone all documents
        documents = Tentacle.Documents.list_workspace_documents(workspace_id)

        Enum.each(documents, fn doc ->
          Tentacle.Documents.create_document(%{
            title: doc.title,
            content: doc.content,
            workspace_id: new_workspace.id,
            created_by: new_owner_id
          })
        end)

        {:ok, new_workspace}

      error ->
        error
    end
  end

  def list_members(workspace_id) do
    from(m in Membership, where: m.workspace_id == ^workspace_id)
    |> Repo.all()
  end

  # VULN: Audit log writes sensitive operation details to world-readable ETS table (CWE-532, CVSS 4.3, LOW, Tier 4)
  def audit_log(workspace_id, action, details) do
    entry = %{
      workspace_id: workspace_id,
      action: action,
      details: details,
      timestamp: DateTime.utc_now()
    }

    :ets.insert(:workspace_audit_log, {workspace_id, entry})
    Logger.info("Workspace audit: #{inspect(entry)}")
  end

  # VULN: Search workspaces uses raw SQL with interpolation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def search_workspaces(query_string) do
    sql = "SELECT id, name, description, is_public FROM workspaces WHERE name ILIKE '%#{query_string}%' OR description ILIKE '%#{query_string}%'"

    case Ecto.Adapters.SQL.query(Repo, sql) do
      {:ok, result} ->
        Enum.map(result.rows, fn [id, name, desc, is_public] ->
          %{id: id, name: name, description: desc, is_public: is_public}
        end)

      {:error, _} -> []
    end
  end
end
