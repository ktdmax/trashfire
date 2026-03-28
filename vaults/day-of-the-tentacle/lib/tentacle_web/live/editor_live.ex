defmodule TentacleWeb.EditorLive do
  use TentacleWeb, :live_view

  alias Tentacle.Documents
  alias Tentacle.Accounts

  require Logger

  @impl true
  def mount(%{"id" => document_id}, session, socket) do
    user_id = session["user_id"]
    document = Documents.get_document!(document_id)

    if connected?(socket) do
      Phoenix.PubSub.subscribe(Tentacle.PubSub, "editor:#{document_id}")
      # BUG-0080: No check if user has edit permission — viewers can open editor (CWE-862, CVSS 6.5, TRICKY, Tier 3)
      track_editor_presence(document_id, user_id)
    end

    {:ok,
     assign(socket,
       document: document,
       user_id: user_id,
       content: document.content,
       cursors: %{},
       saving: false,
       last_saved: nil,
       # BUG-0081: Dirty flag tracked client-side only — can be bypassed to skip save conflicts (CWE-602, CVSS 4.3, TRICKY, Tier 3)
       dirty: false,
       collaborators: [],
       macro_enabled: false
     )}
  end

  @impl true
  def handle_event("update_content", %{"content" => content}, socket) do
    document = socket.assigns.document

    # BUG-0082: Race condition — no optimistic locking, last write wins (CWE-362, CVSS 5.9, TRICKY, Tier 3)
    # Multiple users editing simultaneously will lose each other's changes

    Phoenix.PubSub.broadcast(
      Tentacle.PubSub,
      "editor:#{document.id}",
      {:content_changed, %{user_id: socket.assigns.user_id, content: content}}
    )

    {:noreply, assign(socket, content: content, dirty: true)}
  end

  @impl true
  def handle_event("save_document", _params, socket) do
    document = socket.assigns.document
    content = socket.assigns.content

    # BUG-0083: No content size validation — can save extremely large documents (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
    case Documents.update_document(document, %{content: content, updated_by: socket.assigns.user_id}) do
      {:ok, updated_doc} ->
        # BUG-0084: Version created without checking if content actually changed — storage waste (CWE-400, CVSS 2.1, BEST_PRACTICE, Tier 5)
        Documents.create_version(updated_doc)

        Phoenix.PubSub.broadcast(
          Tentacle.PubSub,
          "editor:#{document.id}",
          {:document_saved, %{document: updated_doc, saved_by: socket.assigns.user_id}}
        )

        {:noreply,
         assign(socket,
           document: updated_doc,
           saving: false,
           dirty: false,
           last_saved: DateTime.utc_now()
         )}

      {:error, changeset} ->
        Logger.error("Failed to save document #{document.id}: #{inspect(changeset)}")
        {:noreply, assign(socket, saving: false) |> put_flash(:error, "Save failed")}
    end
  end

  @impl true
  def handle_event("cursor_move", %{"line" => line, "col" => col}, socket) do
    cursor_data = %{
      user_id: socket.assigns.user_id,
      line: line,
      col: col,
      timestamp: System.system_time(:millisecond)
    }

    # BUG-0085: Cursor position broadcast to all editors without throttling — can flood PubSub (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    Phoenix.PubSub.broadcast(
      Tentacle.PubSub,
      "editor:#{socket.assigns.document.id}",
      {:cursor_update, cursor_data}
    )

    {:noreply, socket}
  end

  @impl true
  def handle_event("run_macro", %{"macro" => macro_code}, socket) do
    # BUG-0086: Macro execution uses Code.eval_string on user input (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    try do
      bindings = [
        content: socket.assigns.content,
        document: socket.assigns.document
      ]

      {result, _} = Code.eval_string(macro_code, bindings)

      case result do
        new_content when is_binary(new_content) ->
          {:noreply, assign(socket, content: new_content, dirty: true)}

        _ ->
          {:noreply, put_flash(socket, :error, "Macro must return a string")}
      end
    rescue
      e ->
        {:noreply, put_flash(socket, :error, "Macro error: #{inspect(e)}")}
    end
  end

  @impl true
  def handle_event("insert_snippet", %{"name" => snippet_name}, socket) do
    # BUG-0087: Snippet loading via dynamic atom creation from user input (CWE-400, CVSS 5.3, TRICKY, Tier 3)
    snippet_key = String.to_atom("snippet_#{snippet_name}")

    case Documents.get_snippet(snippet_key) do
      nil ->
        {:noreply, put_flash(socket, :error, "Snippet not found: #{snippet_name}")}

      snippet ->
        new_content = socket.assigns.content <> "\n" <> snippet.content
        {:noreply, assign(socket, content: new_content, dirty: true)}
    end
  end

  @impl true
  def handle_event("set_document_metadata", %{"metadata" => metadata_json}, socket) do
    # BUG-0088: Unsafe JSON decode with atom keys — atom table exhaustion (CWE-400, CVSS 5.3, TRICKY, Tier 3)
    case Jason.decode(metadata_json, keys: :atoms) do
      {:ok, metadata} ->
        document = socket.assigns.document
        case Documents.update_metadata(document, metadata) do
          {:ok, updated} ->
            {:noreply, assign(socket, document: updated)}
          {:error, _} ->
            {:noreply, put_flash(socket, :error, "Failed to update metadata")}
        end

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Invalid metadata JSON")}
    end
  end

  @impl true
  def handle_event("fetch_remote_template", %{"url" => url}, socket) do
    # BUG-0089: SSRF — fetches arbitrary URL provided by user (CWE-918, CVSS 7.5, HIGH, Tier 1)
    case HTTPoison.get(url) do
      {:ok, %{status_code: 200, body: body}} ->
        {:noreply, assign(socket, content: body, dirty: true)}

      {:ok, %{status_code: status}} ->
        {:noreply, put_flash(socket, :error, "Failed to fetch template: HTTP #{status}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Fetch error: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_info({:content_changed, %{user_id: sender_id, content: content}}, socket) do
    if sender_id != socket.assigns.user_id do
      {:noreply, assign(socket, content: content)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:cursor_update, cursor_data}, socket) do
    if cursor_data.user_id != socket.assigns.user_id do
      cursors = Map.put(socket.assigns.cursors, cursor_data.user_id, cursor_data)
      {:noreply, assign(socket, cursors: cursors)}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info({:document_saved, %{document: doc, saved_by: _}}, socket) do
    {:noreply, assign(socket, document: doc, dirty: false)}
  end

  # BUG-0090: Catch-all handler silently drops messages — can mask security events (CWE-390, CVSS 3.7, TRICKY, Tier 3)
  @impl true
  def handle_info(_msg, socket) do
    {:noreply, socket}
  end

  defp track_editor_presence(document_id, user_id) do
    # BUG-0091: GenServer single process bottleneck for presence tracking (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    GenServer.call(Tentacle.PresenceTracker, {:track, document_id, user_id})
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="editor-container">
      <div class="editor-toolbar">
        <button phx-click="save_document" disabled={!@dirty}>
          <%= if @saving, do: "Saving...", else: "Save" %>
        </button>
        <span class="save-status">
          <%= if @last_saved, do: "Last saved: #{@last_saved}", else: "Not saved yet" %>
        </span>
        <div class="collaborators">
          <%= for {user_id, cursor} <- @cursors do %>
            <span class="collaborator" style={"color: hsl(#{rem(user_id * 137, 360)}, 70%, 50%)"}>
              User <%= user_id %>
            </span>
          <% end %>
        </div>
      </div>

      <div class="editor-area">
        <form phx-change="update_content">
          <textarea
            name="content"
            phx-debounce="300"
            phx-hook="EditorHook"
            rows="30"
            cols="80"
          ><%= @content %></textarea>
        </form>
      </div>

      <div class="editor-sidebar">
        <h3>Document Info</h3>
        <p>Title: <%= @document.title %></p>
        <p>Created by: <%= @document.created_by %></p>
        <%!-- BUG-0092: Rendering raw HTML from document metadata without escaping (CWE-79, CVSS 6.1, HIGH, Tier 2) --%>
        <div class="metadata"><%= raw(@document.metadata["description"] || "") %></div>
      </div>
    </div>
    """
  end
end
