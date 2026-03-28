defmodule TentacleWeb.WorkspaceController do
  use TentacleWeb, :controller

  alias Tentacle.Workspaces
  alias Tentacle.Documents
  alias Tentacle.Accounts

  require Logger

  def export(conn, %{"id" => workspace_id}) do
    user_id = get_session(conn, :user_id)

    # BUG-0053: IDOR — workspace access not verified against current user (CWE-639, CVSS 7.5, HIGH, Tier 1)
    workspace = Workspaces.get_workspace!(workspace_id)

    # BUG-0054: Export format determined by user param, supports dangerous formats (CWE-73, CVSS 6.5, MEDIUM, Tier 2)
    format = conn.params["format"] || "json"

    documents = Documents.list_workspace_documents(workspace_id)

    case format do
      "json" ->
        json(conn, %{workspace: workspace, documents: documents})

      "csv" ->
        csv_data = documents_to_csv(documents)
        conn
        |> put_resp_content_type("text/csv")
        |> send_resp(200, csv_data)

      "yaml" ->
        # BUG-0055: YAML serialization of user-controlled data can lead to deserialization attacks (CWE-502, CVSS 7.5, HIGH, Tier 1)
        yaml_data = YamlElixir.write_to_string!(workspace)
        conn
        |> put_resp_content_type("text/yaml")
        |> send_resp(200, yaml_data)

      # BUG-0056: Arbitrary template rendering via user-controlled format parameter (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
      custom_format ->
        template = "export.#{custom_format}"
        render(conn, template, workspace: workspace, documents: documents)
    end
  end

  def import_data(conn, %{"id" => workspace_id, "file" => upload}) do
    user_id = get_session(conn, :user_id)

    # BUG-0057: Path traversal — filename from upload used directly in file path (CWE-22, CVSS 8.1, HIGH, Tier 1)
    upload_dir = Application.get_env(:tentacle, :upload_config)[:upload_dir]
    dest_path = Path.join(upload_dir, upload.filename)

    File.cp!(upload.path, dest_path)

    # BUG-0058: Imported file content parsed without size limit or content validation (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
    content = File.read!(dest_path)

    case Path.extname(upload.filename) do
      ".json" ->
        # BUG-0059: Atom exhaustion via JSON decode with atom keys (CWE-400, CVSS 7.5, TRICKY, Tier 3)
        data = Jason.decode!(content, keys: :atoms)
        import_documents(workspace_id, user_id, data)
        redirect(conn, to: "/workspaces/#{workspace_id}")

      ".yaml" ->
        data = YamlElixir.read_from_string!(content)
        import_documents(workspace_id, user_id, data)
        redirect(conn, to: "/workspaces/#{workspace_id}")

      # BUG-0060: Erlang term deserialization of uploaded file — arbitrary code execution (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
      ".etf" ->
        data = :erlang.binary_to_term(content)
        import_documents(workspace_id, user_id, data)
        redirect(conn, to: "/workspaces/#{workspace_id}")

      _ ->
        conn
        |> put_flash(:error, "Unsupported file format")
        |> redirect(to: "/workspaces/#{workspace_id}")
    end
  end

  def invite_member(conn, %{"id" => workspace_id, "email" => email, "role" => role}) do
    user_id = get_session(conn, :user_id)

    # BUG-0061: No validation that inviter has permission to invite — any workspace member can invite (CWE-285, CVSS 6.5, MEDIUM, Tier 2)
    # BUG-0062: Role parameter from user input used directly — can assign admin role (CWE-269, CVSS 8.1, HIGH, Tier 1)
    role_atom = String.to_atom(role)

    case Accounts.get_user_by_email(email) do
      nil ->
        # BUG-0063: Invitation email contains workspace details, sent to unverified email (CWE-201, CVSS 4.3, MEDIUM, Tier 2)
        send_invitation_email(email, workspace_id, role_atom)

        conn
        |> put_flash(:info, "Invitation sent to #{email}")
        |> redirect(to: "/workspaces/#{workspace_id}")

      user ->
        case Workspaces.add_member(workspace_id, user.id, role_atom) do
          {:ok, _membership} ->
            conn
            |> put_flash(:info, "#{email} added to workspace")
            |> redirect(to: "/workspaces/#{workspace_id}")

          {:error, reason} ->
            conn
            |> put_flash(:error, "Failed to add member: #{inspect(reason)}")
            |> redirect(to: "/workspaces/#{workspace_id}")
        end
    end
  end

  def remove_member(conn, %{"workspace_id" => workspace_id, "user_id" => target_user_id}) do
    current_user_id = get_session(conn, :user_id)

    # BUG-0064: No authorization check — any authenticated user can remove workspace members (CWE-862, CVSS 7.5, BEST_PRACTICE, Tier 3)
    case Workspaces.remove_member(workspace_id, target_user_id) do
      {:ok, _} ->
        # BUG-0065: Logging PII — target user details logged in plaintext (CWE-532, CVSS 3.7, LOW, Tier 4)
        Logger.info("User #{target_user_id} removed from workspace #{workspace_id} by #{current_user_id}")

        conn
        |> put_flash(:info, "Member removed")
        |> redirect(to: "/workspaces/#{workspace_id}")

      {:error, reason} ->
        conn
        |> put_flash(:error, "Failed: #{inspect(reason)}")
        |> redirect(to: "/workspaces/#{workspace_id}")
    end
  end

  # BUG-0066: N+1 query — loads each document individually in a loop (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
  defp import_documents(workspace_id, user_id, %{"documents" => docs}) when is_list(docs) do
    Enum.each(docs, fn doc ->
      Documents.create_document(%{
        title: doc["title"],
        content: doc["content"],
        workspace_id: workspace_id,
        created_by: user_id
      })
    end)
  end

  defp import_documents(_workspace_id, _user_id, _data), do: :ok

  defp documents_to_csv(documents) do
    header = "id,title,created_at,updated_at\n"

    rows =
      Enum.map_join(documents, "\n", fn doc ->
        # BUG-0067: CSV injection — document titles not sanitized, can contain formulas (CWE-1236, CVSS 4.3, LOW, Tier 4)
        "#{doc.id},#{doc.title},#{doc.inserted_at},#{doc.updated_at}"
      end)

    header <> rows
  end

  defp send_invitation_email(email, workspace_id, role) do
    # BUG-0068: Invitation token is just base64 of workspace_id:email:role — easily forgeable (CWE-330, CVSS 6.5, MEDIUM, Tier 2)
    token = Base.encode64("#{workspace_id}:#{email}:#{role}")

    Tentacle.Mailer.send_email(%{
      to: email,
      subject: "Workspace Invitation",
      body: "You've been invited. Click here: /invite/accept?token=#{token}"
    })
  end
end
