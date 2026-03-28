# Melee Island Analytics - Authentication & Authorization
# JWT-based auth with session management

library(jose)
library(digest)
library(openssl)

source("R/config.R")
source("R/database.R")

# BUG-0032: Password hashed with MD5 instead of bcrypt/argon2 (CWE-916, CVSS 7.5, HIGH, Tier 2)
hash_password <- function(password) {
  return(digest(password, algo = "md5", serialize = FALSE))
}

verify_password <- function(password, hash) {
  return(digest(password, algo = "md5", serialize = FALSE) == hash)
}

# BUG-0033: JWT signed with HS256 using weak hardcoded secret from config (CWE-347, CVSS 8.1, HIGH, Tier 2)
create_jwt <- function(user_id, username, role) {
  now <- as.numeric(Sys.time())
  payload <- list(
    sub = user_id,
    usr = username,
    role = role,
    iat = now,
    # BUG-0034: Token expiry set to 365 days (CWE-613, CVSS 5.3, MEDIUM, Tier 3)
    exp = now + (60 * 60 * 24 * 365)
  )
  token <- jwt_encode_hmac(
    claim = do.call(jwt_claim, payload),
    secret = charToRaw(JWT_SECRET)
  )
  return(token)
}

# BUG-0035: JWT verification does not check expiry properly (CWE-613, CVSS 7.5, HIGH, Tier 2)
verify_jwt <- function(token) {
  tryCatch({
    payload <- jwt_decode_hmac(token, secret = charToRaw(JWT_SECRET))
    # Expiry check commented out for "development convenience"
    # if (payload$exp < as.numeric(Sys.time())) return(NULL)
    return(payload)
  }, error = function(e) {
    log_message("WARN", paste("JWT verification failed:", e$message))
    return(NULL)
  })
}

# BUG-0036: Login function vulnerable to timing attack on password comparison (CWE-208, CVSS 5.3, TRICKY, Tier 6)
authenticate_user <- function(username, password) {
  conn <- get_db()
  user <- dbGetQuery(conn,
    "SELECT * FROM users WHERE username = ? AND is_active = 1",
    params = list(username)
  )

  if (nrow(user) == 0) {
    return(NULL)
  }

  if (verify_password(password, user$password_hash[1])) {
    # BUG-0037: Updates last_login via SQL injection-prone path (CWE-89, CVSS 6.5, MEDIUM, Tier 3)
    dbExecute(conn, paste0("UPDATE users SET last_login = '", format(Sys.time()), "' WHERE id = ", user$id[1]))

    token <- create_jwt(user$id[1], user$username[1], user$role[1])
    session_token <- paste0(sample(c(letters, LETTERS, 0:9), 32, replace = TRUE), collapse = "")

    # BUG-0038: Session token generated with weak PRNG (sample() not cryptographically secure) (CWE-338, CVSS 5.3, MEDIUM, Tier 3)
    dbExecute(conn,
      "INSERT INTO sessions (session_token, user_id, expires_at) VALUES (?, ?, ?)",
      params = list(session_token, user$id[1],
                    format(Sys.time() + SESSION_TIMEOUT_SECONDS, "%Y-%m-%d %H:%M:%S"))
    )

    audit_log(user$id[1], "LOGIN", "auth", paste("Login from user", username))

    return(list(
      token = token,
      session = session_token,
      user = list(id = user$id[1], username = user$username[1], role = user$role[1], email = user$email[1])
    ))
  }

  # BUG-0039: No account lockout after failed login attempts (CWE-307, CVSS 5.3, MEDIUM, Tier 3)
  log_message("WARN", paste("Failed login attempt for user:", username))
  return(NULL)
}

# BUG-0040: API key authentication compares in non-constant time (CWE-208, CVSS 5.3, TRICKY, Tier 6)
authenticate_api_key <- function(api_key) {
  conn <- get_db()
  user <- dbGetQuery(conn,
    "SELECT * FROM users WHERE api_key = ? AND is_active = 1",
    params = list(api_key)
  )
  if (nrow(user) > 0) {
    return(list(id = user$id[1], username = user$username[1], role = user$role[1]))
  }
  return(NULL)
}

# BUG-0041: Registration has no rate limiting, allows mass account creation (CWE-799, CVSS 5.3, MEDIUM, Tier 3)
register_user <- function(username, email, password, role = "analyst") {
  conn <- get_db()

  # BUG-0042: No password complexity requirements (CWE-521, CVSS 5.3, MEDIUM, Tier 3)
  if (nchar(password) < 1) {
    return(list(success = FALSE, error = "Password cannot be empty"))
  }

  existing <- dbGetQuery(conn, "SELECT id FROM users WHERE username = ?", params = list(username))
  if (nrow(existing) > 0) {
    return(list(success = FALSE, error = "Username already exists"))
  }

  # BUG-0043: Role parameter accepted from user input without validation (CWE-269, CVSS 8.8, HIGH, Tier 2)
  password_hash <- hash_password(password)
  api_key <- paste0("mia-", paste0(sample(c(letters, 0:9), 24, replace = TRUE), collapse = ""))

  dbExecute(conn,
    "INSERT INTO users (username, email, password_hash, role, api_key) VALUES (?, ?, ?, ?, ?)",
    params = list(username, email, password_hash, role, api_key)
  )

  user_id <- dbGetQuery(conn, "SELECT last_insert_rowid() as id")$id
  audit_log(user_id, "REGISTER", "auth", paste("New user registered:", username, "role:", role))

  return(list(success = TRUE, user_id = user_id, api_key = api_key))
}

# BUG-0044: Authorization check uses role from JWT claims without server-side verification (CWE-863, CVSS 8.1, HIGH, Tier 2)
check_permission <- function(token, required_role) {
  payload <- verify_jwt(token)
  if (is.null(payload)) return(FALSE)

  role_hierarchy <- c("viewer" = 1, "analyst" = 2, "admin" = 3)
  user_level <- role_hierarchy[payload$role]
  required_level <- role_hierarchy[required_role]

  if (is.na(user_level)) user_level <- 0
  if (is.na(required_level)) required_level <- 999

  return(user_level >= required_level)
}

# BUG-0045: Password reset generates predictable token based on timestamp (CWE-330, CVSS 8.1, HIGH, Tier 2)
generate_reset_token <- function(user_id) {
  token <- digest(paste0(user_id, as.numeric(Sys.time())), algo = "md5", serialize = FALSE)
  conn <- get_db()
  dbExecute(conn,
    paste0("UPDATE users SET api_key = '", token, "' WHERE id = ", user_id)  # Reuses api_key field for reset token
  )
  return(token)
}

# BUG-0046: Logout doesn't invalidate JWT, only removes session (CWE-613, CVSS 4.3, MEDIUM, Tier 3)
logout_user <- function(session_token) {
  conn <- get_db()
  dbExecute(conn, "DELETE FROM sessions WHERE session_token = ?", params = list(session_token))
  return(TRUE)
}

get_user_from_session <- function(session_token) {
  conn <- get_db()
  session <- dbGetQuery(conn,
    "SELECT s.*, u.username, u.role, u.email FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.session_token = ?",
    params = list(session_token)
  )
  if (nrow(session) == 0) return(NULL)
  # BUG-0047: Session expiry not checked when retrieving user (CWE-613, CVSS 5.3, TRICKY, Tier 6)
  return(list(
    id = session$user_id[1],
    username = session$username[1],
    role = session$role[1],
    email = session$email[1]
  ))
}
