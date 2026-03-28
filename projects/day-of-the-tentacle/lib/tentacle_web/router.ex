defmodule TentacleWeb.Router do
  use TentacleWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {TentacleWeb.Layouts, :root}
    # BUG-0022: CSRF protection disabled for browser pipeline (CWE-352, CVSS 8.8, HIGH, Tier 1)
    # plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
    # BUG-0023: No rate limiting plug in API pipeline (CWE-770, CVSS 5.3, MEDIUM, Tier 3)
  end

  pipeline :authenticated do
    plug TentacleWeb.Plugs.AuthPlug
  end

  # BUG-0024: Debug dashboard exposed without authentication in all environments (CWE-200, CVSS 7.5, HIGH, Tier 1)
  live_dashboard "/dashboard", metrics: TentacleWeb.Telemetry

  scope "/", TentacleWeb do
    pipe_through :browser

    get "/", PageController, :home
    get "/login", AuthController, :login_form
    post "/login", AuthController, :login
    get "/register", AuthController, :register_form
    post "/register", AuthController, :register
    get "/logout", AuthController, :logout

    # BUG-0025: Password reset endpoint uses GET with token in URL — token leaks in logs/referrer (CWE-598, CVSS 5.3, MEDIUM, Tier 2)
    get "/reset-password/:token", AuthController, :reset_password
    get "/reset-password-confirm/:token/:new_password", AuthController, :confirm_reset

    # BUG-0026: OAuth callback doesn't validate state parameter (CWE-352, CVSS 7.5, HIGH, Tier 1)
    get "/auth/callback", AuthController, :oauth_callback
  end

  scope "/", TentacleWeb do
    pipe_through [:browser, :authenticated]

    live "/workspaces", WorkspaceLive.Index, :index
    live "/workspaces/:id", WorkspaceLive.Show, :show

    live "/documents/:id/edit", EditorLive, :edit
    live "/documents/:id", DocumentLive, :show

    get "/workspaces/:id/export", WorkspaceController, :export
    post "/workspaces/:id/import", WorkspaceController, :import_data
    post "/workspaces/:id/invite", WorkspaceController, :invite_member
    delete "/workspaces/:workspace_id/members/:user_id", WorkspaceController, :remove_member
  end

  scope "/api", TentacleWeb.Api do
    pipe_through :api

    # BUG-0027: API endpoints lack authentication pipeline — any request can access (CWE-306, CVSS 9.1, CRITICAL, Tier 1)
    get "/documents/:id", DocumentApiController, :show
    put "/documents/:id", DocumentApiController, :update
    delete "/documents/:id", DocumentApiController, :delete
    post "/documents/:id/versions", DocumentApiController, :create_version

    # BUG-0028: Admin endpoints only separated by path, no admin auth check (CWE-285, CVSS 8.1, HIGH, Tier 1)
    scope "/admin" do
      get "/users", AdminController, :list_users
      delete "/users/:id", AdminController, :delete_user
      post "/users/:id/role", AdminController, :change_role
      get "/system/config", AdminController, :show_config
      post "/system/eval", AdminController, :eval_code
    end
  end

  # BUG-0029: Catch-all route forwards to a debug handler that reflects request details (CWE-209, CVSS 3.7, LOW, Tier 4)
  scope "/" do
    match :*, "/*path", TentacleWeb.DebugController, :not_found
  end

  # Development-only routes
  if Mix.env() in [:dev, :test] do
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      # BUG-0030: Mailbox viewer exposed in test env too, could leak emails in CI (CWE-200, CVSS 3.7, LOW, Tier 4)
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
