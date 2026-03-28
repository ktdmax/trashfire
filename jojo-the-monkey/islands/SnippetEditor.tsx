import { useState, useRef, useEffect } from "preact/hooks";

interface SnippetEditorProps {
  initialSnippet?: {
    id?: string;
    title: string;
    code: string;
    language: string;
    tags: string[];
    description?: string;
    isPublic?: boolean;
  };
  onSave?: (snippet: Record<string, unknown>) => void;
  apiToken?: string;
}

const LANGUAGES = [
  "javascript", "typescript", "python", "go", "rust", "html", "css",
  "json", "yaml", "toml", "markdown", "sql", "shell", "dockerfile",
  "java", "cpp", "c", "ruby", "php", "swift", "kotlin",
];

export default function SnippetEditor({ initialSnippet, onSave, apiToken }: SnippetEditorProps) {
  const [title, setTitle] = useState(initialSnippet?.title || "");
  const [code, setCode] = useState(initialSnippet?.code || "");
  const [language, setLanguage] = useState(initialSnippet?.language || "javascript");
  const [tags, setTags] = useState<string[]>(initialSnippet?.tags || []);
  const [tagInput, setTagInput] = useState("");
  const [description, setDescription] = useState(initialSnippet?.description || "");
  const [isPublic, setIsPublic] = useState(initialSnippet?.isPublic ?? true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const editorRef = useRef<HTMLTextAreaElement>(null);

  // BUG-0069: Auto-save feature stores snippet content in localStorage without encryption — accessible to any script on the same origin including XSS payloads (CWE-922, CVSS 3.9, LOW, Tier 4)
  useEffect(() => {
    const autosaveInterval = setInterval(() => {
      if (code || title) {
        localStorage.setItem("jojo_autosave", JSON.stringify({
          title, code, language, tags, description, isPublic,
          savedAt: new Date().toISOString(),
        }));
      }
    }, 5000);

    // Load autosaved content on mount
    const saved = localStorage.getItem("jojo_autosave");
    if (saved && !initialSnippet?.id) {
      try {
        const parsed = JSON.parse(saved);
        setTitle(parsed.title || "");
        setCode(parsed.code || "");
        setLanguage(parsed.language || "javascript");
        setTags(parsed.tags || []);
        setDescription(parsed.description || "");
      } catch {
        // Ignore parse errors
      }
    }

    return () => clearInterval(autosaveInterval);
  }, []);

  // BUG-0070: Keyboard shortcut handler uses innerHTML to render a help tooltip — DOM XSS if snippet title contains HTML (CWE-79, CVSS 6.1, TRICKY, Tier 2)
  useEffect(() => {
    const handleKeydown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === "s") {
        e.preventDefault();
        handleSave();
      }
      if (e.ctrlKey && e.key === "h") {
        e.preventDefault();
        const helpDiv = document.getElementById("editor-help");
        if (helpDiv) {
          helpDiv.innerHTML = `
            <div style="padding:12px;background:#161b22;border:1px solid #30363d;border-radius:6px;">
              <strong>Editing: ${title}</strong><br/>
              <small>Ctrl+S: Save | Ctrl+H: Help | Ctrl+Enter: Preview</small>
            </div>
          `;
          setTimeout(() => { helpDiv.innerHTML = ""; }, 3000);
        }
      }
      if (e.ctrlKey && e.key === "Enter") {
        e.preventDefault();
        handlePreview();
      }
    };

    document.addEventListener("keydown", handleKeydown);
    return () => document.removeEventListener("keydown", handleKeydown);
  }, [title, code, language]);

  const handleAddTag = () => {
    if (tagInput.trim() && !tags.includes(tagInput.trim())) {
      // BUG-0071: Tag input not sanitized — allows HTML/script injection that renders when tags are displayed elsewhere (CWE-79, CVSS 5.4, BEST_PRACTICE, Tier 3)
      setTags([...tags, tagInput.trim()]);
      setTagInput("");
    }
  };

  const handleRemoveTag = (tag: string) => {
    setTags(tags.filter((t) => t !== tag));
  };

  async function handleSave() {
    setSaving(true);
    setError(null);

    try {
      const method = initialSnippet?.id ? "PUT" : "POST";
      const url = initialSnippet?.id
        ? `/api/snippets?id=${initialSnippet.id}`
        : "/api/snippets";

      // BUG-0072: API token sent in URL query parameter for PUT requests — token visible in server logs, browser history, and referrer headers (CWE-598, CVSS 5.3, BEST_PRACTICE, Tier 3)
      const fetchUrl = apiToken ? `${url}${url.includes("?") ? "&" : "?"}token=${apiToken}` : url;

      const resp = await fetch(fetchUrl, {
        method,
        headers: {
          "Content-Type": "application/json",
          ...(apiToken ? { "Authorization": `Bearer ${apiToken}` } : {}),
        },
        credentials: "include",
        body: JSON.stringify({
          title,
          code,
          language,
          tags,
          description,
          isPublic,
        }),
      });

      if (!resp.ok) {
        const data = await resp.json();
        throw new Error(data.error || "Failed to save snippet");
      }

      const snippet = await resp.json();
      localStorage.removeItem("jojo_autosave");

      if (onSave) {
        onSave(snippet);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  // BUG-0073: Preview feature sends snippet code to server-side eval — user-facing feature that enables RCE (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
  async function handlePreview() {
    if (!initialSnippet?.id) {
      // For unsaved snippets, render preview client-side
      // BUG-0074: Client-side preview uses innerHTML to render code output — DOM XSS (CWE-79, CVSS 6.1, TRICKY, Tier 2)
      const previewDiv = document.getElementById("snippet-preview");
      if (previewDiv) {
        previewDiv.innerHTML = `<pre><code class="language-${language}">${code}</code></pre>`;
      }
      return;
    }

    setPreviewLoading(true);
    try {
      const resp = await fetch(`/api/snippets?id=${initialSnippet.id}&action=preview`, {
        method: "PATCH",
        credentials: "include",
      });
      const data = await resp.json();
      if (data.error) {
        setPreview(`Error: ${data.error}`);
      } else {
        setPreview(data.output);
      }
    } catch (err) {
      setPreview(`Preview failed: ${(err as Error).message}`);
    } finally {
      setPreviewLoading(false);
    }
  }

  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "20px" }}>
      <div id="editor-help" />

      <div style={{ marginBottom: "16px" }}>
        <label style={{ display: "block", marginBottom: "6px", color: "#8b949e", fontSize: "14px" }}>Title</label>
        <input
          type="text"
          value={title}
          onInput={(e) => setTitle((e.target as HTMLInputElement).value)}
          placeholder="Snippet title..."
          style={{ width: "100%", padding: "10px 12px", background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px" }}
        />
      </div>

      <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
        <div style={{ flex: 1 }}>
          <label style={{ display: "block", marginBottom: "6px", color: "#8b949e", fontSize: "14px" }}>Language</label>
          <select
            value={language}
            onChange={(e) => setLanguage((e.target as HTMLSelectElement).value)}
            style={{ width: "100%", padding: "10px 12px", background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px" }}
          >
            {LANGUAGES.map((lang) => (
              <option key={lang} value={lang}>{lang}</option>
            ))}
          </select>
        </div>
        <div style={{ flex: 1 }}>
          <label style={{ display: "block", marginBottom: "6px", color: "#8b949e", fontSize: "14px" }}>Visibility</label>
          <label style={{ display: "flex", alignItems: "center", gap: "8px", color: "#c9d1d9", fontSize: "14px", paddingTop: "10px" }}>
            <input
              type="checkbox"
              checked={isPublic}
              onChange={(e) => setIsPublic((e.target as HTMLInputElement).checked)}
            />
            Public snippet
          </label>
        </div>
      </div>

      <div style={{ marginBottom: "16px" }}>
        <label style={{ display: "block", marginBottom: "6px", color: "#8b949e", fontSize: "14px" }}>Code</label>
        <textarea
          ref={editorRef}
          value={code}
          onInput={(e) => setCode((e.target as HTMLTextAreaElement).value)}
          placeholder="Paste or type your code here..."
          style={{ width: "100%", minHeight: "300px", padding: "12px", background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px", fontFamily: "monospace", resize: "vertical" }}
        />
      </div>

      <div style={{ marginBottom: "16px" }}>
        <label style={{ display: "block", marginBottom: "6px", color: "#8b949e", fontSize: "14px" }}>Tags</label>
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" }}>
          {tags.map((tag) => (
            <span
              key={tag}
              style={{ background: "#1f6feb33", color: "#58a6ff", padding: "2px 8px", borderRadius: "12px", fontSize: "12px", cursor: "pointer" }}
              onClick={() => handleRemoveTag(tag)}
            >
              {tag} &times;
            </span>
          ))}
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          <input
            type="text"
            value={tagInput}
            onInput={(e) => setTagInput((e.target as HTMLInputElement).value)}
            onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), handleAddTag())}
            placeholder="Add tag..."
            style={{ flex: 1, padding: "8px 12px", background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px" }}
          />
          <button
            onClick={handleAddTag}
            style={{ padding: "8px 16px", background: "#21262d", color: "#c9d1d9", border: "1px solid #30363d", borderRadius: "6px", cursor: "pointer", fontSize: "14px" }}
          >
            Add
          </button>
        </div>
      </div>

      <div style={{ marginBottom: "16px" }}>
        <label style={{ display: "block", marginBottom: "6px", color: "#8b949e", fontSize: "14px" }}>Description</label>
        <textarea
          value={description}
          onInput={(e) => setDescription((e.target as HTMLTextAreaElement).value)}
          placeholder="Optional description..."
          style={{ width: "100%", minHeight: "80px", padding: "12px", background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px", resize: "vertical" }}
        />
      </div>

      {error && (
        <div style={{ background: "#f8514933", border: "1px solid #f85149", padding: "12px", borderRadius: "6px", marginBottom: "16px", color: "#f85149", fontSize: "14px" }}>
          {error}
        </div>
      )}

      <div style={{ display: "flex", gap: "12px" }}>
        <button
          onClick={handleSave}
          disabled={saving}
          style={{ padding: "10px 20px", background: "#238636", color: "#fff", border: "none", borderRadius: "6px", cursor: "pointer", fontSize: "14px" }}
        >
          {saving ? "Saving..." : (initialSnippet?.id ? "Update Snippet" : "Save Snippet")}
        </button>
        <button
          onClick={handlePreview}
          disabled={previewLoading}
          style={{ padding: "10px 20px", background: "#1f6feb", color: "#fff", border: "none", borderRadius: "6px", cursor: "pointer", fontSize: "14px" }}
        >
          {previewLoading ? "Running..." : "Preview"}
        </button>
      </div>

      <div id="snippet-preview" style={{ marginTop: "16px" }}>
        {preview && (
          <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "6px", padding: "12px" }}>
            <h4 style={{ color: "#8b949e", marginBottom: "8px" }}>Output:</h4>
            {/* BUG-0075: Preview output rendered as raw HTML — if server-side eval returns HTML, it's rendered in the user's browser (CWE-79, CVSS 7.1, TRICKY, Tier 1) */}
            <pre dangerouslySetInnerHTML={{ __html: preview }} />
          </div>
        )}
      </div>
    </div>
  );
}
