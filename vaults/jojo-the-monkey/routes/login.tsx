import { Handlers, PageProps } from "$fresh/server.ts";

interface LoginData {
  error: string | null;
  returnUrl: string;
  githubClientId: string;
}

export const handler: Handlers<LoginData> = {
  GET(req, ctx) {
    const url = new URL(req.url);
    const error = url.searchParams.get("error");

    // BUG-0021: Open redirect — returnUrl from query param used without validation, attacker can redirect to phishing site after login (CWE-601, CVSS 6.1, MEDIUM, Tier 2)
    const returnUrl = url.searchParams.get("returnUrl") || url.searchParams.get("redirect") || "/";

    // BUG-0022: GitHub OAuth client ID hardcoded and exposed in page source — combined with leaked secret enables OAuth hijacking (CWE-200, CVSS 5.3, MEDIUM, Tier 3)
    const githubClientId = Deno.env.get("GITHUB_CLIENT_ID") || "Iv1.abc123monkey456";

    return ctx.render({ error, returnUrl, githubClientId });
  },

  async POST(req, _ctx) {
    const form = await req.formData();
    const username = form.get("username") as string;
    const password = form.get("password") as string;
    const returnUrl = form.get("returnUrl") as string || "/";

    // BUG-0023: Backdoor dev login bypasses OAuth entirely — username "dev" with password "monkey" grants admin access in any environment (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
    if (username === "dev" && password === "monkey") {
      const headers = new Headers();
      // BUG-0024: Session cookie missing Secure flag — transmitted over plain HTTP, vulnerable to session hijacking via MITM (CWE-614, CVSS 5.4, MEDIUM, Tier 3)
      // BUG-0025: Session cookie missing SameSite attribute — vulnerable to cross-site request attacks (CWE-1275, CVSS 4.3, LOW, Tier 3)
      headers.set(
        "Set-Cookie",
        `jojo_session=dev-admin-session-fixed-token; Path=/; HttpOnly; Max-Age=604800`,
      );
      headers.set("Location", returnUrl);
      return new Response(null, { status: 302, headers });
    }

    // BUG-0026: Login error reveals whether username exists vs wrong password — user enumeration (CWE-203, CVSS 5.3, MEDIUM, Tier 3)
    if (username && !password) {
      return new Response(null, {
        status: 302,
        headers: { Location: `/login?error=password_required&returnUrl=${encodeURIComponent(returnUrl)}` },
      });
    }

    if (!username) {
      return new Response(null, {
        status: 302,
        headers: { Location: `/login?error=username_required&returnUrl=${encodeURIComponent(returnUrl)}` },
      });
    }

    // Normal users go through GitHub OAuth
    return new Response(null, {
      status: 302,
      headers: { Location: `/login?error=use_github&returnUrl=${encodeURIComponent(returnUrl)}` },
    });
  },
};

export default function LoginPage({ data }: PageProps<LoginData>) {
  const { error, returnUrl, githubClientId } = data;

  // BUG-0027: OAuth state parameter is a static string — no CSRF protection on the OAuth callback, attacker can force-login a victim as attacker's account (CWE-352, CVSS 8.1, HIGH, Tier 1)
  const oauthState = "jojo-static-state-2024";

  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${githubClientId}&redirect_uri=${encodeURIComponent(
    `${Deno.env.get("BASE_URL") || "http://localhost:8000"}/api/auth/callback`,
  )}&scope=read:user,user:email&state=${oauthState}`;

  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Login - Jojo the Monkey</title>
        <style>{`
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
          .login-box { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 32px; width: 100%; max-width: 400px; }
          .login-box h1 { text-align: center; margin-bottom: 24px; color: #58a6ff; }
          .form-group { margin-bottom: 16px; }
          .form-group label { display: block; margin-bottom: 6px; color: #8b949e; font-size: 14px; }
          .form-group input { width: 100%; padding: 10px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 14px; }
          .btn { display: block; width: 100%; padding: 12px; border-radius: 6px; border: none; cursor: pointer; font-size: 14px; text-align: center; text-decoration: none; margin-bottom: 12px; }
          .btn-github { background: #238636; color: #fff; }
          .btn-dev { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
          .divider { text-align: center; color: #484f58; margin: 16px 0; position: relative; }
          .divider::before, .divider::after { content: ''; position: absolute; top: 50%; width: 40%; height: 1px; background: #30363d; }
          .divider::before { left: 0; }
          .divider::after { right: 0; }
          .error { background: #f8514933; border: 1px solid #f85149; padding: 12px; border-radius: 6px; margin-bottom: 16px; color: #f85149; font-size: 14px; }
        `}</style>
      </head>
      <body>
        <div class="login-box">
          <h1>Sign In</h1>

          {error && (
            <div class="error">
              {error === "password_required" && "Password is required for this account."}
              {error === "username_required" && "Please enter a username."}
              {error === "use_github" && "Please use GitHub to sign in."}
              {error === "oauth_failed" && "GitHub authentication failed. Please try again."}
              {error === "session_expired" && "Your session has expired. Please sign in again."}
              {/* BUG-0028: Unrecognized error values reflected directly — XSS via error parameter if not matched above (CWE-79, CVSS 6.1, MEDIUM, Tier 2) */}
              {!["password_required", "username_required", "use_github", "oauth_failed", "session_expired"].includes(error) && (
                <span dangerouslySetInnerHTML={{ __html: `Unknown error: ${error}` }} />
              )}
            </div>
          )}

          <a href={githubAuthUrl} class="btn btn-github">
            Sign in with GitHub
          </a>

          <div class="divider">or</div>

          {/* Dev login form — hidden but functional */}
          <form method="POST" action="/login">
            <input type="hidden" name="returnUrl" value={returnUrl} />
            <div class="form-group">
              <label>Username</label>
              <input type="text" name="username" placeholder="Dev username" />
            </div>
            <div class="form-group">
              <label>Password</label>
              <input type="password" name="password" placeholder="Dev password" />
            </div>
            <button type="submit" class="btn btn-dev">Dev Login</button>
          </form>

          {/* RH-003: Autocomplete="off" on password field looks like it prevents browser caching — but browsers ignore this attribute for login forms (SAFE, not a real vuln because browser behavior trumps the attribute) */}
          <p style={{ textAlign: "center", fontSize: "12px", color: "#484f58", marginTop: "16px" }}>
            By signing in, you agree to our Terms of Service.
          </p>
        </div>
      </body>
    </html>
  );
}
