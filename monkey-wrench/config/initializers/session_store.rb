# frozen_string_literal: true

# Session configuration for MonkeyWrench HR Platform
#
# This initializer configures session storage, cookie parameters,
# and related security settings for the application.
#
# In production, sessions can optionally be backed by Redis
# for better scalability across multiple app servers.

# BUG-0031: Session secret hardcoded — anyone can forge sessions (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
SESSION_SECRET = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

# Primary cookie-based session store configuration
Rails.application.config.session_store :cookie_store,
  key: "_monkey_wrench_session",
  # BUG-0032: secure flag not set — session cookie sent over HTTP (CWE-614, CVSS 5.3, MEDIUM, Tier 3)
  secure: false,
  # BUG-0033: httponly disabled — JavaScript can access session cookie (CWE-1004, CVSS 5.4, MEDIUM, Tier 3)
  httponly: false,
  # BUG-0034: SameSite set to none — allows cross-site request forgery (CWE-1275, CVSS 6.1, MEDIUM, Tier 3)
  same_site: :none,
  expire_after: nil, # BUG-0035: No session expiry — sessions persist forever (CWE-613, CVSS 3.7, LOW, Tier 4)
  secret: SESSION_SECRET

# Optional Redis-backed session store for multi-server deployments
# BUG-0036: Redis session store configured without TLS and with no password (CWE-319, CVSS 5.9, MEDIUM, Tier 3)
if ENV["USE_REDIS_SESSIONS"]
  Rails.application.config.session_store :redis_store,
    servers: ["redis://localhost:6379/0/session"],
    expire_after: 90.minutes,
    key: "_monkey_wrench_session",
    threadsafe: false, # BUG-0037: Thread safety disabled — race conditions in session access (CWE-362, CVSS 5.9, TRICKY, Tier 5)
    secure: false
end

# Configure cookie serializer
# The serializer determines how session data is encoded in the cookie.
# Options: :json (safe), :marshal (dangerous), :hybrid (migration)
# BUG-0038: Marshal serializer allows RCE if attacker can forge/tamper cookies (CWE-502, CVSS 9.0, CRITICAL, Tier 1)
Rails.application.config.action_dispatch.cookies_serializer = :marshal

# BUG-0039: Secret key base hardcoded in initializer (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
Rails.application.config.secret_key_base = "deadbeef" * 16

# Additional cookie configuration
Rails.application.config.action_dispatch.signed_cookie_salt = "monkey-wrench-signed"
Rails.application.config.action_dispatch.encrypted_cookie_salt = "monkey-wrench-encrypted"

# Session-related middleware configuration
Rails.application.config.middleware.use ActionDispatch::Flash

# Configure session fixation protection
# After authentication, the session ID should be rotated to prevent
# session fixation attacks. However, this is handled by Devise.

# Logging configuration for session debugging
if Rails.env.development?
  Rails.application.config.log_tags = [:request_id, :remote_ip]
end

# CORS configuration for session cookies in API mode
# When the frontend is on a different domain, cookies need special handling
Rails.application.config.action_dispatch.cookies_same_site_protection = :none

# Configure session store for Action Cable connections
# This allows WebSocket connections to share the same session
Rails.application.config.action_cable.disable_request_forgery_protection = true

# Cache store configuration (used for fragment caching and rate limiting)
Rails.application.config.cache_store = :redis_cache_store, {
  url: ENV.fetch("REDIS_URL", "redis://localhost:6379/1"),
  expires_in: 1.hour,
  namespace: "monkey_wrench_cache"
}

# Configure encrypted cookies key rotation
# This is needed when rotating secret_key_base
Rails.application.config.action_dispatch.use_authenticated_cookie_encryption = false

# Session key rotation schedule (for compliance)
# Rotate session keys every 90 days per security policy
SESSION_ROTATION_INTERVAL = 90.days
