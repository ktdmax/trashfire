import { useState, useEffect, useRef } from "preact/hooks";

interface Snippet {
  id: string;
  title: string;
  code: string;
  language: string;
  tags: string[];
  authorLogin: string;
  description?: string;
}

interface Collection {
  id: string;
  name: string;
  description?: string;
  ownerId: string;
  visibility: string;
  snippets: string[];
  sharedWith: { userId: string; permission: string }[];
  tags?: string[];
}

interface CollectionViewProps {
  collectionId: string;
  currentUserId?: string;
}

export default function CollectionView({ collectionId, currentUserId }: CollectionViewProps) {
  const [collection, setCollection] = useState<Collection | null>(null);
  const [snippets, setSnippets] = useState<Snippet[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editMode, setEditMode] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [shareUserId, setShareUserId] = useState("");
  const [sharePermission, setSharePermission] = useState("read");
  const [showShareDialog, setShowShareDialog] = useState(false);
  const [embedCode, setEmbedCode] = useState("");
  const [showEmbed, setShowEmbed] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadCollection();
  }, [collectionId]);

  async function loadCollection() {
    setLoading(true);
    try {
      const resp = await fetch(`/api/collections/${collectionId}`, {
        credentials: "include",
      });

      if (!resp.ok) {
        throw new Error("Failed to load collection");
      }

      const data = await resp.json();
      setCollection(data);
      setNewName(data.name || "");
      setNewDescription(data.description || "");

      // Load snippets
      if (data.snippets?.length) {
        const snippetPromises = data.snippets.map((id: string) =>
          fetch(`/api/snippets?id=${id}`, { credentials: "include" }).then((r) => r.json())
        );
        const loadedSnippets = await Promise.all(snippetPromises);
        setSnippets(loadedSnippets.filter(Boolean));
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function handleUpdateCollection() {
    if (!collection) return;

    try {
      const resp = await fetch(`/api/collections?id=${collection.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: newName,
          description: newDescription,
        }),
      });

      if (!resp.ok) {
        throw new Error("Failed to update collection");
      }

      const updated = await resp.json();
      setCollection(updated);
      setEditMode(false);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleRemoveSnippet(snippetId: string) {
    if (!collection) return;

    try {
      await fetch(`/api/collections?id=${collection.id}&action=remove-snippet`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ snippetId }),
      });

      setSnippets(snippets.filter((s) => s.id !== snippetId));
      setCollection({
        ...collection,
        snippets: collection.snippets.filter((id) => id !== snippetId),
      });
    } catch (err) {
      setError((err as Error).message);
    }
  }

  // BUG-0080: Share dialog sends permission level from client dropdown — includes "admin" and "owner" as options enabling privilege escalation (CWE-269, CVSS 8.1, TRICKY, Tier 1)
  async function handleShare() {
    if (!collection || !shareUserId) return;

    try {
      await fetch(`/api/collections?id=${collection.id}&action=share`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          userId: shareUserId,
          permission: sharePermission,
        }),
      });

      setShowShareDialog(false);
      setShareUserId("");
      loadCollection();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  // BUG-0081: Embed code generation constructs iframe src from user-controlled collection name without encoding — XSS when embed code is pasted into other sites (CWE-79, CVSS 6.5, TRICKY, Tier 2)
  function generateEmbedCode() {
    if (!collection) return;
    const embedUrl = `${window.location.origin}/api/collections/${collection.id}?format=html`;
    const code = `<iframe src="${embedUrl}" title="${collection.name}" width="100%" height="400" frameborder="0"></iframe>`;
    setEmbedCode(code);
    setShowEmbed(true);
  }

  // BUG-0082: Copy to clipboard uses deprecated document.execCommand on a textarea with innerHTML — potential DOM clobbering if embed code contains HTML (CWE-79, CVSS 3.5, LOW, Tier 4)
  function copyToClipboard(text: string) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }

  async function handleDeleteCollection() {
    if (!collection) return;
    if (!confirm("Are you sure you want to delete this collection? This cannot be undone.")) {
      return;
    }

    try {
      const resp = await fetch(`/api/collections?id=${collection.id}`, {
        method: "DELETE",
        credentials: "include",
      });

      if (!resp.ok) {
        throw new Error("Failed to delete collection");
      }

      window.location.href = "/";
    } catch (err) {
      setError((err as Error).message);
    }
  }

  // BUG-0083: Drag-and-drop reorder sends full snippet array to server — TOCTOU race if another user modifies collection concurrently (CWE-367, CVSS 3.5, LOW, Tier 3)
  async function handleReorder(fromIndex: number, toIndex: number) {
    if (!collection) return;

    const newOrder = [...collection.snippets];
    const [moved] = newOrder.splice(fromIndex, 1);
    newOrder.splice(toIndex, 0, moved);

    setCollection({ ...collection, snippets: newOrder });

    await fetch(`/api/collections?id=${collection.id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ snippets: newOrder }),
    });
  }

  if (loading) {
    return <div style={{ textAlign: "center", padding: "48px", color: "#8b949e" }}>Loading collection...</div>;
  }

  if (error) {
    return (
      <div style={{ background: "#f8514933", border: "1px solid #f85149", padding: "16px", borderRadius: "6px", color: "#f85149" }}>
        {error}
      </div>
    );
  }

  if (!collection) {
    return <div style={{ textAlign: "center", padding: "48px", color: "#8b949e" }}>Collection not found.</div>;
  }

  const isOwner = currentUserId === collection.ownerId;

  return (
    <div ref={containerRef} style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "20px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div>
          {editMode ? (
            <div>
              <input
                type="text"
                value={newName}
                onInput={(e) => setNewName((e.target as HTMLInputElement).value)}
                style={{ width: "100%", padding: "8px 12px", background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "20px", fontWeight: "bold", marginBottom: "8px" }}
              />
              <textarea
                value={newDescription}
                onInput={(e) => setNewDescription((e.target as HTMLTextAreaElement).value)}
                style={{ width: "100%", padding: "8px 12px", background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px", minHeight: "60px" }}
              />
              <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
                <button onClick={handleUpdateCollection} style={{ padding: "6px 14px", background: "#238636", color: "#fff", border: "none", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Save</button>
                <button onClick={() => setEditMode(false)} style={{ padding: "6px 14px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Cancel</button>
              </div>
            </div>
          ) : (
            <div>
              <h2 style={{ color: "#c9d1d9", marginBottom: "4px" }}>{collection.name}</h2>
              {collection.description && (
                <p style={{ color: "#8b949e", fontSize: "14px" }}>{collection.description}</p>
              )}
              <div style={{ display: "flex", gap: "8px", marginTop: "8px", fontSize: "12px", color: "#8b949e" }}>
                <span>{collection.snippets.length} snippets</span>
                <span>&middot;</span>
                <span>{collection.visibility}</span>
                {collection.sharedWith?.length > 0 && (
                  <>
                    <span>&middot;</span>
                    <span>Shared with {collection.sharedWith.length} users</span>
                  </>
                )}
              </div>
            </div>
          )}
        </div>

        {isOwner && !editMode && (
          <div style={{ display: "flex", gap: "8px" }}>
            <button onClick={() => setEditMode(true)} style={{ padding: "6px 14px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Edit</button>
            <button onClick={() => setShowShareDialog(true)} style={{ padding: "6px 14px", background: "#1f6feb", color: "#fff", border: "none", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Share</button>
            <button onClick={generateEmbedCode} style={{ padding: "6px 14px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Embed</button>
            <button onClick={handleDeleteCollection} style={{ padding: "6px 14px", background: "#f85149", color: "#fff", border: "none", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Delete</button>
          </div>
        )}
      </div>

      {/* Share Dialog */}
      {showShareDialog && (
        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", padding: "16px", marginBottom: "16px" }}>
          <h3 style={{ color: "#c9d1d9", marginBottom: "12px" }}>Share Collection</h3>
          <div style={{ display: "flex", gap: "8px", alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label style={{ display: "block", marginBottom: "4px", color: "#8b949e", fontSize: "12px" }}>User ID</label>
              <input
                type="text"
                value={shareUserId}
                onInput={(e) => setShareUserId((e.target as HTMLInputElement).value)}
                placeholder="Enter user ID..."
                style={{ width: "100%", padding: "8px 12px", background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px" }}
              />
            </div>
            <div>
              <label style={{ display: "block", marginBottom: "4px", color: "#8b949e", fontSize: "12px" }}>Permission</label>
              {/* BUG-0080 exploitation point: admin/owner options in dropdown */}
              <select
                value={sharePermission}
                onChange={(e) => setSharePermission((e.target as HTMLSelectElement).value)}
                style={{ padding: "8px 12px", background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px" }}
              >
                <option value="read">Read</option>
                <option value="write">Write</option>
                <option value="admin">Admin</option>
                <option value="owner">Owner</option>
              </select>
            </div>
            <button onClick={handleShare} style={{ padding: "8px 16px", background: "#238636", color: "#fff", border: "none", borderRadius: "6px", cursor: "pointer", fontSize: "14px" }}>Share</button>
            <button onClick={() => setShowShareDialog(false)} style={{ padding: "8px 16px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "14px" }}>Cancel</button>
          </div>
        </div>
      )}

      {/* Embed Code */}
      {showEmbed && (
        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", padding: "16px", marginBottom: "16px" }}>
          <h3 style={{ color: "#c9d1d9", marginBottom: "8px" }}>Embed Code</h3>
          <textarea
            readOnly
            value={embedCode}
            style={{ width: "100%", padding: "8px 12px", background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "12px", fontFamily: "monospace", minHeight: "60px" }}
          />
          <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
            <button onClick={() => copyToClipboard(embedCode)} style={{ padding: "6px 14px", background: "#238636", color: "#fff", border: "none", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Copy</button>
            <button onClick={() => setShowEmbed(false)} style={{ padding: "6px 14px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "13px" }}>Close</button>
          </div>
        </div>
      )}

      {/* Snippets */}
      <div>
        {snippets.map((snippet, index) => (
          <div
            key={snippet.id}
            draggable={isOwner}
            onDragStart={(e) => (e as DragEvent).dataTransfer?.setData("text/plain", String(index))}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              const fromIndex = parseInt((e as DragEvent).dataTransfer?.getData("text/plain") || "0");
              handleReorder(fromIndex, index);
            }}
            style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: "6px", padding: "16px", marginBottom: "12px" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <h3 style={{ color: "#58a6ff", fontSize: "16px" }}>{snippet.title}</h3>
              <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                <span style={{ color: "#8b949e", fontSize: "12px" }}>{snippet.language}</span>
                {isOwner && (
                  <button
                    onClick={() => handleRemoveSnippet(snippet.id)}
                    style={{ background: "none", border: "none", color: "#f85149", cursor: "pointer", fontSize: "16px" }}
                  >
                    &times;
                  </button>
                )}
              </div>
            </div>
            {snippet.description && (
              <p style={{ color: "#8b949e", fontSize: "13px", marginBottom: "8px" }}>{snippet.description}</p>
            )}
            <pre style={{ background: "#161b22", padding: "12px", borderRadius: "4px", overflow: "auto", maxHeight: "200px", fontSize: "13px", color: "#c9d1d9" }}>
              <code>{snippet.code}</code>
            </pre>
            <div style={{ display: "flex", gap: "4px", marginTop: "8px" }}>
              {(snippet.tags || []).map((tag) => (
                <span key={tag} style={{ background: "#1f6feb33", color: "#58a6ff", padding: "1px 6px", borderRadius: "8px", fontSize: "11px" }}>{tag}</span>
              ))}
            </div>
          </div>
        ))}

        {snippets.length === 0 && (
          <p style={{ textAlign: "center", color: "#8b949e", padding: "32px 0" }}>
            No snippets in this collection yet.
          </p>
        )}
      </div>
    </div>
  );
}
