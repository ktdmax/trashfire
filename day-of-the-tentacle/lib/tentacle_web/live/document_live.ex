defmodule TentacleWeb.DocumentLive do
  use TentacleWeb, :live_view

  alias Tentacle.Documents
  alias Tentacle.Workspaces
  alias Tentacle.Accounts

  require Logger

  @impl true
  def mount(%{"id" => document_id}, session, socket) do
    user_id = session["user_id"]

    # BUG-0069: Document loaded without checking user's workspace membership (CWE-862, CVSS 7.5, MEDIUM, Tier 2)
    document = Documents.get_document!(document_id)

    if connected?(socket) do
      Phoenix.PubSub.subscribe(Tentacle.PubSub, "document:#{document_id}")
      # BUG-0070: Broadcasting user presence with full user details including email (CWE-359, CVSS 4.3, LOW, Tier 4)
      user = Accounts.get_user!(user_id)
      broadcast_presence(document_id, user)
    end

    # BUG-0071: Version history loaded without pagination — memory bomb on large docs (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
    versions = Documents.list_all_versions(document_id)

    {:ok,
     assign(socket,
       document: document,
       user_id: user_id,
       versions: versions,
       active_users: [],
       show_versions: false,
       search_results: [],
       search_query: ""
     )}
  end

  @impl true
  def handle_event("search_documents", %{"query" => query}, socket) do
    # BUG-0072: Raw SQL injection via user search query interpolated into Ecto raw SQL (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    results = Documents.search_documents_raw(query, socket.assigns.user_id)

    {:noreply, assign(socket, search_results: results, search_query: query)}
  end

  @impl true
  def handle_event("toggle_versions", _params, socket) do
    {:noreply, assign(socket, show_versions: !socket.assigns.show_versions)}
  end

  @impl true
  def handle_event("restore_version", %{"version_id" => version_id}, socket) do
    document = socket.assigns.document

    # BUG-0073: No authorization check for version restore — any viewer can restore (CWE-862, CVSS 6.5, MEDIUM, Tier 2)
    case Documents.restore_version(document.id, version_id) do
      {:ok, updated_doc} ->
        Phoenix.PubSub.broadcast(
          Tentacle.PubSub,
          "document:#{document.id}",
          {:document_updated, updated_doc}
        )
        {:noreply, assign(socket, document: updated_doc)}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Restore failed: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("share_document", %{"email" => email, "permission" => permission}, socket) do
    document = socket.assigns.document

    # BUG-0074: Permission level from user input not validated against allowed values (CWE-20, CVSS 6.5, MEDIUM, Tier 2)
    perm_atom = String.to_atom(permission)

    case Documents.share_document(document.id, email, perm_atom) do
      {:ok, _share} ->
        {:noreply, put_flash(socket, :info, "Document shared with #{email}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to share: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("delete_document", _params, socket) do
    document = socket.assigns.document

    # BUG-0075: No ownership check — any user with document access can delete (CWE-862, CVSS 7.5, BEST_PRACTICE, Tier 3)
    case Documents.delete_document(document.id) do
      {:ok, _} ->
        {:noreply,
         socket
         |> put_flash(:info, "Document deleted")
         |> push_navigate(to: "/workspaces")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Delete failed: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("run_template", %{"template_code" => template_code}, socket) do
    # BUG-0076: Code injection — user-provided template code evaluated with Code.eval_string (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    try do
      {result, _bindings} = Code.eval_string(template_code, [document: socket.assigns.document])
      {:noreply, assign(socket, template_result: result)}
    rescue
      e ->
        # BUG-0077: Full exception details including stack trace sent to client (CWE-209, CVSS 3.7, LOW, Tier 4)
        {:noreply, put_flash(socket, :error, "Template error: #{Exception.format(:error, e, __STACKTRACE__)}")}
    end
  end

  @impl true
  def handle_event("export_document", %{"format" => format}, socket) do
    document = socket.assigns.document

    case format do
      "html" ->
        # BUG-0078: Document content rendered as raw HTML without sanitization (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
        html_content = "<html><body>#{document.content}</body></html>"
        {:noreply, push_event(socket, "download", %{content: html_content, filename: "#{document.title}.html"})}

      "markdown" ->
        {:noreply, push_event(socket, "download", %{content: document.content, filename: "#{document.title}.md"})}

      _ ->
        {:noreply, put_flash(socket, :error, "Unsupported format")}
    end
  end

  @impl true
  def handle_info({:document_updated, document}, socket) do
    {:noreply, assign(socket, document: document)}
  end

  @impl true
  def handle_info({:user_joined, user_info}, socket) do
    active_users = [user_info | socket.assigns.active_users] |> Enum.uniq_by(& &1.id)
    {:noreply, assign(socket, active_users: active_users)}
  end

  @impl true
  def handle_info({:user_left, user_id}, socket) do
    active_users = Enum.reject(socket.assigns.active_users, &(&1.id == user_id))
    {:noreply, assign(socket, active_users: active_users)}
  end

  # BUG-0079: Catch-all handle_info accepts any message — PubSub spoofing vector (CWE-345, CVSS 5.3, TRICKY, Tier 3)
  @impl true
  def handle_info(msg, socket) do
    Logger.debug("DocumentLive received unknown message: #{inspect(msg)}")
    {:noreply, socket}
  end

  defp broadcast_presence(document_id, user) do
    Phoenix.PubSub.broadcast(
      Tentacle.PubSub,
      "document:#{document_id}",
      {:user_joined, %{id: user.id, name: user.name, email: user.email, avatar: user.avatar_url}}
    )
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="document-viewer">
      <div class="document-header">
        <h1><%= @document.title %></h1>
        <div class="active-users">
          <%= for user <- @active_users do %>
            <span class="user-badge"><%= user.name %></span>
          <% end %>
        </div>
      </div>

      <div class="search-bar">
        <form phx-submit="search_documents">
          <input type="text" name="query" value={@search_query} placeholder="Search documents..." />
          <button type="submit">Search</button>
        </form>
      </div>

      <div class="document-content">
        <%!-- RH-004: This uses Phoenix's default HTML escaping in HEEx templates, which is safe --%>
        <div class="content"><%= @document.content %></div>
      </div>

      <div class="document-actions">
        <button phx-click="toggle_versions">Version History</button>
        <button phx-click="delete_document" data-confirm="Are you sure?">Delete</button>
      </div>

      <%= if @show_versions do %>
        <div class="version-history">
          <%= for version <- @versions do %>
            <div class="version-entry">
              <span>Version <%= version.version_number %> by <%= version.created_by %></span>
              <button phx-click="restore_version" phx-value-version_id={version.id}>Restore</button>
            </div>
          <% end %>
        </div>
      <% end %>
    </div>
    """
  end
end
