import { Handlers, PageProps } from "$fresh/server.ts";
import { getSession, getUserById } from "../utils/auth.ts";
import { getRecentSnippets, getPublicCollections } from "../utils/db.ts";

interface IndexData {
  user: Record<string, unknown> | null;
  snippets: Record<string, unknown>[];
  collections: Record<string, unknown>[];
  query: string;
  announcement: string;
}

export const handler: Handlers<IndexData> = {
  async GET(req, ctx) {
    const url = new URL(req.url);
    const query = url.searchParams.get("q") || "";
    // BUG-0019: Announcement parameter rendered without sanitization — reflected XSS via URL parameter (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
    const announcement = url.searchParams.get("announcement") || "";

    const session = await getSession(req);
    let user = null;
    if (session?.userId) {
      user = await getUserById(session.userId);
    }

    const snippets = await getRecentSnippets(20, query);
    const collections = await getPublicCollections();

    return ctx.render({
      user,
      snippets,
      collections,
      query,
      announcement,
    });
  },
};

export default function IndexPage({ data }: PageProps<IndexData>) {
  const { user, snippets, collections, query, announcement } = data;

  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Jojo the Monkey - Bookmark & Snippet Manager</title>
        <link
          rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css"
        />
        <style>{`
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; }
          .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
          .header { display: flex; justify-content: space-between; align-items: center; padding: 16px 0; border-bottom: 1px solid #30363d; margin-bottom: 24px; }
          .header h1 { font-size: 24px; color: #58a6ff; }
          .nav-links a { color: #58a6ff; text-decoration: none; margin-left: 16px; }
          .search-bar { margin-bottom: 24px; }
          .search-bar input { width: 100%; padding: 12px 16px; background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 16px; }
          .snippet-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 16px; }
          .snippet-card h3 { color: #58a6ff; margin-bottom: 8px; }
          .snippet-card pre { background: #0d1117; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 14px; }
          .tags { display: flex; gap: 6px; margin-top: 8px; }
          .tag { background: #1f6feb33; color: #58a6ff; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
          .btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 14px; }
          .btn-primary { background: #238636; color: #fff; }
          .btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
          .announcement { background: #1f1d2e; border: 1px solid #6e40c9; padding: 12px; border-radius: 6px; margin-bottom: 16px; }
          .collection-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; margin-bottom: 32px; }
          .collection-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }
          .user-info { display: flex; align-items: center; gap: 8px; }
          .user-info img { width: 32px; height: 32px; border-radius: 50%; }
          .footer { text-align: center; padding: 32px 0; color: #484f58; border-top: 1px solid #30363d; margin-top: 48px; }
        `}</style>
      </head>
      <body>
        <div class="container">
          <header class="header">
            <h1>Jojo the Monkey</h1>
            <nav class="nav-links">
              {user
                ? (
                  <div class="user-info">
                    <img src={user.avatarUrl as string} alt="avatar" />
                    <span>{user.login as string}</span>
                    <a href="/api/auth/logout">Logout</a>
                  </div>
                )
                : <a href="/login" class="btn btn-primary">Sign in with GitHub</a>}
            </nav>
          </header>

          {/* BUG-0019 exploitation point: announcement rendered as raw HTML */}
          {announcement && (
            <div
              class="announcement"
              dangerouslySetInnerHTML={{ __html: announcement }}
            />
          )}

          <div class="search-bar">
            <form method="GET" action="/">
              <input
                type="text"
                name="q"
                placeholder="Search snippets by title, tag, or code..."
                value={query}
              />
            </form>
          </div>

          <h2 style={{ marginBottom: "16px" }}>Public Collections</h2>
          <div class="collection-grid">
            {collections.map((coll) => (
              <div class="collection-card" key={coll.id as string}>
                <h3>{coll.name as string}</h3>
                <p style={{ color: "#8b949e", fontSize: "14px" }}>
                  {(coll.snippets as unknown[])?.length || 0} snippets
                </p>
                <a
                  href={`/api/collections/${coll.id}?format=html`}
                  style={{ color: "#58a6ff", fontSize: "14px" }}
                >
                  View Collection
                </a>
              </div>
            ))}
          </div>

          <h2 style={{ marginBottom: "16px" }}>Recent Snippets</h2>
          {snippets.map((snippet) => (
            <div class="snippet-card" key={snippet.id as string}>
              <h3>{snippet.title as string}</h3>
              <p style={{ color: "#8b949e", fontSize: "12px", marginBottom: "8px" }}>
                by {snippet.authorLogin as string || "anonymous"} &middot;{" "}
                {snippet.language as string}
              </p>
              {/* BUG-0020: Snippet code content rendered as raw HTML — stored XSS if attacker saves malicious snippet content (CWE-79, CVSS 8.1, HIGH, Tier 1) */}
              <pre>
                <code dangerouslySetInnerHTML={{ __html: snippet.highlightedCode as string || snippet.code as string }} />
              </pre>
              <div class="tags">
                {((snippet.tags as string[]) || []).map((tag) => (
                  <span class="tag" key={tag}>{tag}</span>
                ))}
              </div>
            </div>
          ))}

          {snippets.length === 0 && (
            <p style={{ textAlign: "center", color: "#8b949e", padding: "48px 0" }}>
              No snippets found. {user ? "Create your first snippet!" : "Sign in to start saving snippets."}
            </p>
          )}

          <footer class="footer">
            <p>Jojo the Monkey &copy; 2024 &mdash; Built with Deno Fresh</p>
          </footer>
        </div>

        {/* Load islands */}
        <script type="module" src="/_frsh/js/main.js"></script>
      </body>
    </html>
  );
}
