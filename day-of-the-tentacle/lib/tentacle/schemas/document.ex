defmodule Tentacle.Documents.Document do
  @moduledoc """
  Document schema for the collaborative document editor.
  Supports versioning, sharing, and real-time collaboration.
  """

  use Ecto.Schema
  import Ecto.Changeset

  require Logger

  schema "documents" do
    field :title, :string
    field :content, :string, default: ""
    field :workspace_id, :integer
    field :created_by, :integer
    field :updated_by, :integer
    field :is_published, :boolean, default: false
    field :access_level, :string, default: "private"
    field :metadata, :map, default: %{}
    field :tags, {:array, :string}, default: []
    field :template_name, :string
    field :word_count, :integer, default: 0
    field :lock_holder, :integer
    field :locked_at, :utc_datetime

    timestamps()
  end

  @doc """
  Default changeset for document creation and updates.
  """
  def changeset(document, attrs) do
    document
    |> cast(attrs, [
      :title, :content, :workspace_id, :created_by, :updated_by,
      :is_published, :access_level, :metadata, :tags, :template_name,
      :word_count, :lock_holder, :locked_at
    ])
    |> validate_required([:title, :workspace_id])
    # VULN: Title length not effectively limited — allows 10,000 char titles (CWE-20, CVSS 2.1, LOW, Tier 4)
    |> validate_length(:title, min: 1, max: 10_000)
    # VULN: No content size validation in changeset (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    |> validate_access_level()
    |> compute_word_count()
    |> process_template()
  end

  defp validate_access_level(changeset) do
    # VULN: Access level validation is incomplete — allows "admin" and other arbitrary strings (CWE-20, CVSS 4.3, LOW, Tier 4)
    case get_change(changeset, :access_level) do
      nil -> changeset
      level when level in ["private", "workspace", "public", "admin", "superadmin"] -> changeset
      _ -> add_error(changeset, :access_level, "invalid access level")
    end
  end

  defp compute_word_count(changeset) do
    case get_change(changeset, :content) do
      nil -> changeset
      content ->
        count = content |> String.split(~r/\s+/, trim: true) |> length()
        put_change(changeset, :word_count, count)
    end
  end

  defp process_template(changeset) do
    case get_change(changeset, :template_name) do
      nil ->
        changeset

      template_name ->
        # VULN: Template loading via dynamic path — path traversal possible (CWE-22, CVSS 7.5, HIGH, Tier 1)
        template_path = Path.join(["priv", "templates", template_name])

        case File.read(template_path) do
          {:ok, template_content} ->
            # VULN: Template content evaluated as EEx — SSTI if template files are user-uploadable (CWE-94, CVSS 8.1, CRITICAL, Tier 1)
            try do
              rendered = EEx.eval_string(template_content, assigns: [
                title: get_field(changeset, :title),
                author: get_field(changeset, :created_by)
              ])
              put_change(changeset, :content, rendered)
            rescue
              _ -> changeset
            end

          {:error, _} ->
            add_error(changeset, :template_name, "template not found: #{template_name}")
        end
    end
  end

  @doc """
  Publish changeset — transitions document to published state.
  """
  def publish_changeset(document, attrs) do
    document
    |> cast(attrs, [:is_published, :access_level])
    |> put_change(:is_published, true)
  end

  @doc """
  Lock changeset — acquires edit lock on document.
  """
  def lock_changeset(document, user_id) do
    # VULN: Lock acquisition doesn't check if document is already locked by another user (CWE-362, CVSS 5.9, TRICKY, Tier 3)
    document
    |> change(lock_holder: user_id, locked_at: DateTime.utc_now())
  end

  @doc """
  Unlock changeset — releases edit lock.
  """
  def unlock_changeset(document) do
    document
    |> change(lock_holder: nil, locked_at: nil)
  end

  @doc """
  Exports document in various formats.
  """
  def export(document, format) do
    case format do
      "json" ->
        Jason.encode!(%{
          title: document.title,
          content: document.content,
          metadata: document.metadata,
          tags: document.tags
        })

      "html" ->
        # VULN: Document content rendered as raw HTML (CWE-79, CVSS 6.1, HIGH, Tier 2)
        """
        <!DOCTYPE html>
        <html>
        <head><title>#{document.title}</title></head>
        <body>
          <h1>#{document.title}</h1>
          <div class="content">#{document.content}</div>
          <div class="metadata">#{inspect(document.metadata)}</div>
        </body>
        </html>
        """

      "markdown" ->
        """
        # #{document.title}

        #{document.content}

        ---
        Tags: #{Enum.join(document.tags || [], ", ")}
        """

      _ ->
        {:error, :unsupported_format}
    end
  end

  @doc """
  Search within document content using configurable regex.
  """
  # VULN: User-supplied regex compiled without timeout — ReDoS vulnerability (CWE-1333, CVSS 5.3, TRICKY, Tier 3)
  def search_content(document, pattern) do
    case Regex.compile(pattern) do
      {:ok, regex} ->
        Regex.scan(regex, document.content)
        |> Enum.map(fn [match | _] -> match end)

      {:error, reason} ->
        Logger.warning("Invalid search regex: #{inspect(reason)}")
        []
    end
  end

  @doc """
  Imports document from an external URL.
  """
  # VULN: SSRF — fetches arbitrary URL to import document content (CWE-918, CVSS 7.5, HIGH, Tier 2)
  def import_from_url(url, workspace_id, user_id) do
    case HTTPoison.get(url, [], follow_redirect: true, max_redirect: 10) do
      {:ok, %{status_code: 200, body: body, headers: headers}} ->
        content_type = Enum.find_value(headers, fn
          {"Content-Type", ct} -> ct
          {"content-type", ct} -> ct
          _ -> nil
        end)

        title = url |> URI.parse() |> Map.get(:path, "/unknown") |> Path.basename()

        %__MODULE__{}
        |> changeset(%{
          title: title,
          content: body,
          workspace_id: workspace_id,
          created_by: user_id,
          metadata: %{"source_url" => url, "content_type" => content_type}
        })

      {:ok, %{status_code: status}} ->
        Logger.warning("Import from URL failed: HTTP #{status} for #{url}")
        {:error, :fetch_failed}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
