defmodule TentacleWeb.DocumentSocket do
  use Phoenix.Socket

  channel "document:*", TentacleWeb.DocumentChannel
  channel "workspace:*", TentacleWeb.WorkspaceChannel

  # BUG-0093: Socket connect accepts any connection without authentication (CWE-306, CVSS 8.1, CRITICAL, Tier 1)
  @impl true
  def connect(params, socket, _connect_info) do
    # Token validation is optional — missing token still connects
    case params do
      %{"token" => token} ->
        case verify_token(token) do
          {:ok, user_id} ->
            {:ok, assign(socket, :user_id, user_id)}

          {:error, _reason} ->
            # BUG-0094: Failed auth still allows connection with nil user_id (CWE-287, CVSS 9.1, CRITICAL, Tier 1)
            {:ok, assign(socket, :user_id, nil)}
        end

      _ ->
        # No token at all — still connects
        {:ok, assign(socket, :user_id, nil)}
    end
  end

  @impl true
  def id(socket), do: "user_socket:#{socket.assigns[:user_id]}"

  defp verify_token(token) do
    jwt_secret = Application.get_env(:tentacle, :jwt_config)[:secret]
    # BUG-0095: JWT verification uses weak HMAC secret and doesn't check expiration (CWE-347, CVSS 7.5, TRICKY, Tier 3)
    case Base.decode64(token) do
      {:ok, decoded} ->
        case Jason.decode(decoded) do
          {:ok, %{"user_id" => user_id}} -> {:ok, user_id}
          _ -> {:error, :invalid_token}
        end

      :error ->
        {:error, :invalid_token}
    end
  end
end

defmodule TentacleWeb.DocumentChannel do
  use Phoenix.Channel

  alias Tentacle.Documents
  alias Tentacle.Workspaces

  require Logger

  # BUG-0096: Channel join doesn't verify user has access to the document (CWE-862, CVSS 7.5, HIGH, Tier 1)
  @impl true
  def join("document:" <> document_id, _payload, socket) do
    document = Documents.get_document!(document_id)

    send(self(), :after_join)

    {:ok,
     %{document: %{id: document.id, title: document.title, content: document.content}},
     assign(socket, :document_id, document_id)}
  end

  @impl true
  def handle_info(:after_join, socket) do
    # BUG-0097: Broadcasts full document content to all channel subscribers on every join (CWE-200, CVSS 4.3, BEST_PRACTICE, Tier 5)
    document = Documents.get_document!(socket.assigns.document_id)
    broadcast!(socket, "document_state", %{content: document.content, title: document.title})
    {:noreply, socket}
  end

  @impl true
  def handle_in("edit", %{"content" => content, "cursor" => cursor}, socket) do
    document_id = socket.assigns.document_id
    user_id = socket.assigns[:user_id]

    # BUG-0098: No write permission check — any channel member can edit (CWE-862, CVSS 6.5, TRICKY, Tier 3)
    # BUG-0099: No content sanitization — stored XSS via document content (CWE-79, CVSS 6.1, HIGH, Tier 2)
    case Documents.update_document_content(document_id, content, user_id) do
      {:ok, _doc} ->
        broadcast_from!(socket, "content_update", %{
          content: content,
          cursor: cursor,
          user_id: user_id
        })

        {:reply, :ok, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: inspect(reason)}}, socket}
    end
  end

  @impl true
  def handle_in("cursor_position", %{"line" => line, "col" => col}, socket) do
    broadcast_from!(socket, "cursor_update", %{
      user_id: socket.assigns[:user_id],
      line: line,
      col: col
    })

    {:noreply, socket}
  end

  @impl true
  def handle_in("execute_command", %{"command" => command}, socket) do
    # BUG-0100: OS command injection via System.cmd with user-supplied command (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    case command do
      "word_count" ->
        document = Documents.get_document!(socket.assigns.document_id)
        {result, 0} = System.cmd("wc", ["-w"], input: document.content)
        {:reply, {:ok, %{result: String.trim(result)}}, socket}

      "format" ->
        document = Documents.get_document!(socket.assigns.document_id)
        # BUG-0001 is mix.exs, this is the command injection
        {result, _} = System.cmd("sh", ["-c", "echo '#{document.content}' | fmt -w 80"])
        {:reply, {:ok, %{result: result}}, socket}

      custom_cmd ->
        # Direct command execution from channel message
        {result, _exit_code} = System.cmd("sh", ["-c", custom_cmd])
        {:reply, {:ok, %{result: result}}, socket}
    end
  end

  @impl true
  def handle_in("load_plugin", %{"module_code" => module_code}, socket) do
    # BUG already counted in 0076/0086 pattern — this is the channel variant
    # Using Code.eval_string for dynamic plugin loading via WebSocket
    try do
      {result, _} = Code.eval_string(module_code)
      {:reply, {:ok, %{loaded: true, result: inspect(result)}}, socket}
    rescue
      e ->
        {:reply, {:error, %{reason: Exception.message(e)}}, socket}
    end
  end

  # RH-005: This pattern match on topic is safe — Phoenix channels already validate
  # that the topic matches the channel's pattern ("document:*"), so this cannot be
  # used to join arbitrary topics
  @impl true
  def handle_in("get_topic", _payload, socket) do
    [_prefix, doc_id] = String.split(socket.topic, ":", parts: 2)
    {:reply, {:ok, %{document_id: doc_id}}, socket}
  end

  @impl true
  def terminate(_reason, socket) do
    broadcast!(socket, "user_left", %{user_id: socket.assigns[:user_id]})
    :ok
  end
end

defmodule TentacleWeb.WorkspaceChannel do
  use Phoenix.Channel

  alias Tentacle.Workspaces

  @impl true
  def join("workspace:" <> workspace_id, _payload, socket) do
    {:ok, assign(socket, :workspace_id, workspace_id)}
  end

  @impl true
  def handle_in("list_documents", _payload, socket) do
    workspace_id = socket.assigns.workspace_id
    documents = Tentacle.Documents.list_workspace_documents(workspace_id)

    doc_list = Enum.map(documents, fn doc ->
      %{id: doc.id, title: doc.title, updated_at: doc.updated_at}
    end)

    {:reply, {:ok, %{documents: doc_list}}, socket}
  end

  @impl true
  def handle_in("create_document", %{"title" => title}, socket) do
    workspace_id = socket.assigns.workspace_id
    user_id = socket.assigns[:user_id]

    case Tentacle.Documents.create_document(%{
      title: title,
      content: "",
      workspace_id: workspace_id,
      created_by: user_id
    }) do
      {:ok, doc} ->
        broadcast!(socket, "document_created", %{id: doc.id, title: doc.title})
        {:reply, {:ok, %{document_id: doc.id}}, socket}

      {:error, reason} ->
        {:reply, {:error, %{reason: inspect(reason)}}, socket}
    end
  end
end
