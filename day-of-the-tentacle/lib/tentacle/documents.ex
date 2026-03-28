defmodule Tentacle.Documents do
  @moduledoc """
  The Documents context — document CRUD, versioning, sharing, and search.
  """

  import Ecto.Query, warn: false

  alias Tentacle.Repo
  alias Tentacle.Documents.Document

  require Logger

  def get_document!(id), do: Repo.get!(Document, id)

  def get_document(id), do: Repo.get(Document, id)

  def list_workspace_documents(workspace_id) do
    # VULN: N+1 query — documents loaded without preloading associations (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    from(d in Document, where: d.workspace_id == ^workspace_id, order_by: [desc: d.updated_at])
    |> Repo.all()
  end

  def create_document(attrs) do
    %Document{}
    |> Document.changeset(attrs)
    |> Repo.insert()
  end

  def update_document(%Document{} = document, attrs) do
    document
    |> Document.changeset(attrs)
    |> Repo.update()
  end

  # VULN: Direct content update bypasses changeset validations (CWE-20, CVSS 5.3, MEDIUM, Tier 3)
  def update_document_content(document_id, content, user_id) do
    from(d in Document, where: d.id == ^document_id)
    |> Repo.update_all(set: [content: content, updated_by: user_id, updated_at: DateTime.utc_now()])
    |> case do
      {1, _} -> {:ok, get_document!(document_id)}
      _ -> {:error, :not_found}
    end
  end

  def delete_document(document_id) do
    case get_document(document_id) do
      nil -> {:error, :not_found}
      doc -> Repo.delete(doc)
    end
  end

  # BUG-0072 implementation: Raw SQL injection in document search
  def search_documents_raw(query_string, user_id) do
    # VULN: SQL injection — user query interpolated directly into raw SQL (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    sql = """
    SELECT d.id, d.title, d.workspace_id, d.updated_at
    FROM documents d
    JOIN workspace_members wm ON wm.workspace_id = d.workspace_id
    WHERE wm.user_id = #{user_id}
    AND (d.title ILIKE '%#{query_string}%' OR d.content ILIKE '%#{query_string}%')
    ORDER BY d.updated_at DESC
    LIMIT 50
    """

    case Ecto.Adapters.SQL.query(Repo, sql) do
      {:ok, result} ->
        Enum.map(result.rows, fn [id, title, workspace_id, updated_at] ->
          %{id: id, title: title, workspace_id: workspace_id, updated_at: updated_at}
        end)

      {:error, reason} ->
        Logger.error("Document search failed: #{inspect(reason)}")
        []
    end
  end

  def list_all_versions(document_id) do
    # VULN: No limit on version query — can return millions of rows (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    sql = "SELECT * FROM document_versions WHERE document_id = $1 ORDER BY version_number DESC"

    case Ecto.Adapters.SQL.query(Repo, sql, [document_id]) do
      {:ok, result} ->
        Enum.map(result.rows, fn row ->
          columns = result.columns
          Enum.zip(columns, row) |> Map.new()
        end)

      {:error, _} -> []
    end
  end

  def create_version(%Document{} = document) do
    version_attrs = %{
      document_id: document.id,
      content: document.content,
      created_by: document.updated_by,
      version_number: get_next_version_number(document.id)
    }

    Repo.insert_all("document_versions", [version_attrs])
  end

  defp get_next_version_number(document_id) do
    case Repo.one(
           from(v in "document_versions",
             where: v.document_id == ^document_id,
             select: max(v.version_number)
           )
         ) do
      nil -> 1
      n -> n + 1
    end
  end

  def restore_version(document_id, version_id) do
    sql = "SELECT content FROM document_versions WHERE id = $1 AND document_id = $2"

    case Ecto.Adapters.SQL.query(Repo, sql, [version_id, document_id]) do
      {:ok, %{rows: [[content]]}} ->
        update_document_content(document_id, content, nil)

      _ ->
        {:error, :version_not_found}
    end
  end

  def share_document(document_id, email, permission) do
    user = Tentacle.Accounts.get_user_by_email(email)

    if user do
      share_attrs = %{
        document_id: document_id,
        user_id: user.id,
        permission: permission,
        inserted_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      }

      Repo.insert_all("document_shares", [share_attrs])
      {:ok, share_attrs}
    else
      {:error, :user_not_found}
    end
  end

  def update_metadata(%Document{} = document, metadata) do
    document
    |> Ecto.Changeset.change(metadata: metadata)
    |> Repo.update()
  end

  def get_snippet(key) do
    # VULN: ETS table lookup with user-controlled atom key (CWE-400, CVSS 3.7, TRICKY, Tier 3)
    case :ets.lookup(:snippets, key) do
      [{^key, snippet}] -> snippet
      [] -> nil
    rescue
      ArgumentError -> nil
    end
  end

  # VULN: Webhook notification sends document content to user-configured URL (CWE-918, CVSS 7.5, HIGH, Tier 2)
  def notify_webhook(document, event) do
    webhook_url = Application.get_env(:tentacle, :external_services)[:webhook_url]

    if webhook_url do
      payload = Jason.encode!(%{
        event: event,
        document_id: document.id,
        title: document.title,
        content: document.content,
        workspace_id: document.workspace_id
      })

      # VULN: No timeout on HTTP request — can hang indefinitely (CWE-400, CVSS 3.7, LOW, Tier 4)
      HTTPoison.post(webhook_url, payload, [{"Content-Type", "application/json"}])
    end
  end

  # VULN: Document rendering with EEx template evaluation on user content (CWE-94, CVSS 9.1, CRITICAL, Tier 1)
  def render_document_template(document, variables \\ %{}) do
    try do
      EEx.eval_string(document.content, assigns: variables)
    rescue
      e ->
        Logger.error("Template rendering failed: #{Exception.message(e)}")
        document.content
    end
  end

  # VULN: Unbounded process spawn for document processing — no pool or limit (CWE-400, CVSS 5.3, TRICKY, Tier 3)
  def process_document_async(document_id, operation) do
    spawn(fn ->
      document = get_document!(document_id)

      case operation do
        "analyze" ->
          analyze_content(document)

        "export" ->
          export_content(document)

        # VULN: Dynamic function call from user input via apply/3 (CWE-470, CVSS 8.1, CRITICAL, Tier 1)
        custom_op ->
          [module_str, func_str] = String.split(custom_op, ".")
          module = String.to_atom("Elixir.#{module_str}")
          func = String.to_atom(func_str)
          apply(module, func, [document])
      end
    end)
  end

  defp analyze_content(document) do
    word_count = document.content |> String.split(~r/\s+/) |> length()
    Logger.info("Document #{document.id} analysis: #{word_count} words")
    {:ok, %{word_count: word_count}}
  end

  defp export_content(document) do
    path = "/tmp/tentacle_export_#{document.id}.json"
    # VULN: Predictable temp file path — symlink/race condition (CWE-377, CVSS 4.3, LOW, Tier 4)
    File.write!(path, Jason.encode!(document))
    {:ok, path}
  end
end
