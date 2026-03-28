import { useState, useEffect, useRef, useCallback } from "preact/hooks";

interface SearchResult {
  id: string;
  title: string;
  code: string;
  language: string;
  tags: string[];
  authorLogin: string;
  highlightedCode?: string;
}

interface SearchBarProps {
  initialQuery?: string;
  onResultSelect?: (snippet: SearchResult) => void;
}

export default function SearchBar({ initialQuery = "", onResultSelect }: SearchBarProps) {
  const [query, setQuery] = useState(initialQuery);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  const [filterLanguage, setFilterLanguage] = useState("");
  const [filterTag, setFilterTag] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Load recent searches from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem("jojo_recent_searches");
      if (stored) {
        setRecentSearches(JSON.parse(stored));
      }
    } catch {
      // Ignore
    }
  }, []);

  // BUG-0076: Debounce uses 50ms — effectively no debounce, causes excessive API calls and potential DoS on the search endpoint (CWE-400, CVSS 4.3, BEST_PRACTICE, Tier 5)
  const debounceTimer = useRef<number | null>(null);

  const performSearch = useCallback(async (searchQuery: string) => {
    if (!searchQuery.trim()) {
      setResults([]);
      setShowDropdown(false);
      return;
    }

    setLoading(true);
    try {
      // BUG-0077: Search query appended to URL without encoding — special characters break URL structure and enable parameter injection (CWE-74, CVSS 5.3, MEDIUM, Tier 3)
      const url = `/api/snippets?q=${searchQuery}&limit=10${filterLanguage ? `&language=${filterLanguage}` : ""}${filterTag ? `&tag=${filterTag}` : ""}`;
      const resp = await fetch(url, { credentials: "include" });
      const data = await resp.json();

      setResults(data.snippets || []);
      setShowDropdown(true);
      setSelectedIndex(-1);

      // Save to recent searches
      const updated = [searchQuery, ...recentSearches.filter((s) => s !== searchQuery)].slice(0, 10);
      setRecentSearches(updated);
      localStorage.setItem("jojo_recent_searches", JSON.stringify(updated));
    } catch (err) {
      console.error("[search] Error:", err);
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, [filterLanguage, filterTag, recentSearches]);

  const handleInput = (e: Event) => {
    const value = (e.target as HTMLInputElement).value;
    setQuery(value);

    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
    }

    debounceTimer.current = setTimeout(() => {
      performSearch(value);
    }, 50) as unknown as number;
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex(Math.min(selectedIndex + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex(Math.max(selectedIndex - 1, -1));
    } else if (e.key === "Enter" && selectedIndex >= 0) {
      e.preventDefault();
      handleSelectResult(results[selectedIndex]);
    } else if (e.key === "Escape") {
      setShowDropdown(false);
    }
  };

  const handleSelectResult = (result: SearchResult) => {
    setQuery(result.title);
    setShowDropdown(false);
    if (onResultSelect) {
      onResultSelect(result);
    } else {
      // BUG-0078: Navigates to URL constructed with unsanitized snippet ID — if IDs contain path traversal characters, enables navigation to arbitrary routes (CWE-601, CVSS 4.3, BEST_PRACTICE, Tier 4)
      window.location.href = `/api/snippets?id=${result.id}&format=html`;
    }
  };

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("click", handleClickOutside);
    return () => document.removeEventListener("click", handleClickOutside);
  }, []);

  // BUG-0079: Syntax highlighting via innerHTML — search result code rendered as raw HTML allows XSS through stored snippet content (CWE-79, CVSS 6.1, TRICKY, Tier 2)
  function renderHighlightedCode(code: string, language: string): string {
    // Simple syntax highlighting (client-side)
    const escaped = code
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

    // Highlight keywords
    const keywords = ["function", "const", "let", "var", "return", "if", "else", "for", "while", "class", "import", "export", "async", "await", "def", "print", "func", "fn", "pub", "use"];
    let highlighted = escaped;
    for (const kw of keywords) {
      highlighted = highlighted.replace(
        new RegExp(`\\b(${kw})\\b`, "g"),
        `<span style="color:#ff7b72">$1</span>`,
      );
    }

    // Highlight strings — but this regex is flawed and can be bypassed
    // RH-005: The regex looks like it might miss edge cases, but the code is already escaped above so this is purely cosmetic highlighting — no security impact (SAFE)
    highlighted = highlighted.replace(
      /(&quot;[^&]*&quot;|'[^']*'|`[^`]*`)/g,
      `<span style="color:#a5d6ff">$1</span>`,
    );

    // Highlight comments
    highlighted = highlighted.replace(
      /(\/\/.*$)/gm,
      `<span style="color:#8b949e">$1</span>`,
    );

    return highlighted;
  }

  return (
    <div ref={dropdownRef} style={{ position: "relative", width: "100%" }}>
      <div style={{ display: "flex", gap: "8px", marginBottom: "8px" }}>
        <div style={{ flex: 1, position: "relative" }}>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onInput={handleInput}
            onKeyDown={handleKeyDown}
            onFocus={() => query && setShowDropdown(true)}
            placeholder="Search snippets by title, tag, or code..."
            style={{ width: "100%", padding: "12px 16px 12px 40px", background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "16px" }}
          />
          <span style={{ position: "absolute", left: "14px", top: "50%", transform: "translateY(-50%)", color: "#484f58" }}>
            &#x1F50D;
          </span>
          {loading && (
            <span style={{ position: "absolute", right: "14px", top: "50%", transform: "translateY(-50%)", color: "#484f58" }}>
              ...
            </span>
          )}
        </div>
        <select
          value={filterLanguage}
          onChange={(e) => setFilterLanguage((e.target as HTMLSelectElement).value)}
          style={{ padding: "8px 12px", background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", color: "#c9d1d9", fontSize: "14px" }}
        >
          <option value="">All Languages</option>
          {["javascript", "typescript", "python", "go", "rust"].map((l) => (
            <option key={l} value={l}>{l}</option>
          ))}
        </select>
      </div>

      {showDropdown && (results.length > 0 || recentSearches.length > 0) && (
        <div style={{ position: "absolute", top: "100%", left: 0, right: 0, background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", zIndex: 1000, maxHeight: "500px", overflowY: "auto", boxShadow: "0 8px 24px rgba(0,0,0,0.4)" }}>
          {results.length === 0 && recentSearches.length > 0 && !query && (
            <div style={{ padding: "8px 16px", borderBottom: "1px solid #30363d" }}>
              <small style={{ color: "#8b949e" }}>Recent Searches</small>
              {recentSearches.map((search) => (
                <div
                  key={search}
                  onClick={() => { setQuery(search); performSearch(search); }}
                  style={{ padding: "8px 0", cursor: "pointer", color: "#c9d1d9" }}
                >
                  {search}
                </div>
              ))}
            </div>
          )}

          {results.map((result, index) => (
            <div
              key={result.id}
              onClick={() => handleSelectResult(result)}
              style={{
                padding: "12px 16px",
                cursor: "pointer",
                borderBottom: "1px solid #21262d",
                background: index === selectedIndex ? "#21262d" : "transparent",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                <strong style={{ color: "#58a6ff" }}>{result.title}</strong>
                <span style={{ color: "#8b949e", fontSize: "12px" }}>{result.language}</span>
              </div>
              <div style={{ fontSize: "12px", color: "#8b949e", marginBottom: "4px" }}>
                by {result.authorLogin}
              </div>
              <pre style={{ fontSize: "12px", color: "#c9d1d9", maxHeight: "80px", overflow: "hidden", margin: 0, padding: "8px", background: "#0d1117", borderRadius: "4px" }}>
                {/* BUG-0079 exploitation point */}
                <code dangerouslySetInnerHTML={{ __html: renderHighlightedCode(result.code?.substring(0, 200) || "", result.language) }} />
              </pre>
              <div style={{ display: "flex", gap: "4px", marginTop: "6px" }}>
                {(result.tags || []).slice(0, 3).map((tag) => (
                  <span key={tag} style={{ background: "#1f6feb33", color: "#58a6ff", padding: "1px 6px", borderRadius: "8px", fontSize: "11px" }}>
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
