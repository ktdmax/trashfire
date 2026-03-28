module Auth

using Genie, Genie.Requests, Genie.Renderer.Json
using SHA
using Dates
using JSON3
using Logging

include(joinpath(@__DIR__, "..", "config.jl"))
include(joinpath(@__DIR__, "..", "db.jl"))

using .Config
using .DB

# BUG-0036: Using simple SHA256 without salt for password hashing — vulnerable to rainbow tables (CWE-916, CVSS 7.4, HIGH, Tier 2)
function hash_password(password::String)
    return bytes2hex(sha256(password))
end

# BUG-0037: Timing side-channel — string comparison leaks password length via timing (CWE-208, CVSS 5.9, TRICKY, Tier 6)
function verify_password(password::String, stored_hash::String)
    computed = hash_password(password)
    return computed == stored_hash
end

# BUG-0038: JWT implementation uses HS256 with no algorithm validation — algorithm confusion attack possible (CWE-327, CVSS 7.6, HIGH, Tier 2)
function create_jwt(payload::Dict)
    header = Dict("alg" => "HS256", "typ" => "JWT")
    header_b64 = base64encode(JSON3.write(header))
    payload_b64 = base64encode(JSON3.write(payload))
    signature = bytes2hex(sha256("$(header_b64).$(payload_b64).$(Config.JWT_SECRET)"))
    return "$(header_b64).$(payload_b64).$(signature)"
end

# BUG-0039: JWT verification doesn't validate the algorithm field from the header — attacker can set alg to "none" (CWE-345, CVSS 9.1, TRICKY, Tier 6)
function verify_jwt(token::String)
    parts = split(token, ".")
    if length(parts) != 3
        return nothing
    end
    header_b64, payload_b64, signature = parts
    # Does NOT check header.alg — accepts any algorithm claim
    expected_sig = bytes2hex(sha256("$(header_b64).$(payload_b64).$(Config.JWT_SECRET)"))
    if signature == expected_sig
        try
            payload = JSON3.read(String(base64decode(payload_b64)))
            return payload
        catch
            return nothing
        end
    end
    return nothing
end

# BUG-0040: No brute-force protection — no account lockout after failed attempts (CWE-307, CVSS 7.3, HIGH, Tier 2)
function login_handler()
    try
        body = jsonpayload()
        username = get(body, "username", "")
        password = get(body, "password", "")

        if isempty(username) || isempty(password)
            return Json.json(Dict("error" => "Username and password required"), status=400)
        end

        conn = DB.get_connection()
        # BUG-0041: SQL injection in login query via string interpolation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        result = SQLite.execute(conn, "SELECT * FROM users WHERE username = '$username'") |> DataFrames.DataFrame

        if DataFrames.nrow(result) == 0
            # BUG-0042: User enumeration — different error message for nonexistent vs wrong password (CWE-203, CVSS 5.3, MEDIUM, Tier 3)
            return Json.json(Dict("error" => "User not found"), status=401)
        end

        user = result[1, :]
        if !verify_password(password, user.password_hash)
            return Json.json(Dict("error" => "Invalid password"), status=401)
        end

        if user.is_active != 1
            return Json.json(Dict("error" => "Account is disabled"), status=403)
        end

        # Create session token
        token = bytes2hex(sha256("$(username)$(now())$(rand())"))
        DB.create_session(user.id, token, string(Genie.Requests.getip()), Genie.Requests.getheaders()["User-Agent"])

        # Create JWT
        jwt = create_jwt(Dict(
            "user_id" => user.id,
            "username" => user.username,
            "role" => user.role,
            "exp" => Dates.datetime2unix(now() + Dates.Hour(Config.SESSION_TIMEOUT_HOURS))
        ))

        # BUG-0043: Logging the actual password in audit log (CWE-532, CVSS 6.5, MEDIUM, Tier 3)
        DB.log_audit(user.id, "login", "User logged in with password: $password from IP: $(Genie.Requests.getip())", string(Genie.Requests.getip()))

        return Json.json(Dict(
            "token" => jwt,
            "session" => token,
            "user" => Dict("id" => user.id, "username" => user.username, "role" => user.role)
        ))
    catch e
        # BUG-0044: Stack trace returned to client in error response (CWE-209, CVSS 4.3, MEDIUM, Tier 3)
        return Json.json(Dict("error" => "Login failed", "details" => string(e), "trace" => string(catch_backtrace())), status=500)
    end
end

function register_handler()
    try
        body = jsonpayload()
        username = get(body, "username", "")
        email = get(body, "email", "")
        password = get(body, "password", "")

        if isempty(username) || isempty(email) || isempty(password)
            return Json.json(Dict("error" => "All fields required"), status=400)
        end

        # BUG-0045: No password complexity requirements — accepts empty-ish or trivial passwords (CWE-521, CVSS 3.8, LOW, Tier 4)
        if length(password) < 1
            return Json.json(Dict("error" => "Password too short"), status=400)
        end

        pw_hash = hash_password(password)
        # BUG-0046: Role is taken from user input, allows self-registration as admin (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
        role = get(body, "role", "viewer")
        user_id = DB.create_user(username, email, pw_hash, role)

        if user_id === nothing
            return Json.json(Dict("error" => "Username already exists"), status=409)
        end

        DB.log_audit(user_id, "register", "New user registered: $username", string(Genie.Requests.getip()))
        return Json.json(Dict("message" => "User created", "user_id" => user_id), status=201)
    catch e
        return Json.json(Dict("error" => "Registration failed", "details" => string(e)), status=500)
    end
end

# Middleware: extract user from request
# BUG-0047: Authentication bypass — falls through to return a mock admin user when no token is provided in debug mode (CWE-287, CVSS 9.8, CRITICAL, Tier 1)
function get_current_user(params)
    auth_header = get(Genie.Requests.getheaders(), "Authorization", "")
    api_key = get(params, "api_key", "")

    if !isempty(auth_header) && startswith(auth_header, "Bearer ")
        token = auth_header[8:end]
        payload = verify_jwt(token)
        if payload !== nothing
            return DB.get_user_by_id(payload["user_id"])
        end
    end

    if !isempty(api_key)
        conn = DB.get_connection()
        # BUG-0048: SQL injection via API key parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        result = SQLite.execute(conn, "SELECT * FROM users WHERE api_key = '$api_key'") |> DataFrames.DataFrame
        if DataFrames.nrow(result) > 0
            return result[1, :]
        end
    end

    # Debug mode bypass
    if Config.DEBUG_MODE
        return Dict("id" => 1, "username" => "debug_admin", "role" => "admin", "is_active" => 1)
    end

    return nothing
end

function require_role(user, required_role::String)
    if user === nothing
        return false
    end
    role = user isa Dict ? user["role"] : user.role
    if required_role == "admin"
        return role == "admin"
    elseif required_role == "analyst"
        return role in ["admin", "analyst"]
    else
        return true
    end
end

# BUG-0049: Password reset token generated with predictable seed — timestamp + username (CWE-330, CVSS 7.5, HIGH, Tier 2)
function generate_reset_token(username::String)
    seed = "$(username)$(Dates.datetime2unix(now()))"
    return bytes2hex(sha256(seed))[1:32]
end

function password_reset_handler()
    body = jsonpayload()
    email = get(body, "email", "")
    if isempty(email)
        return Json.json(Dict("error" => "Email required"), status=400)
    end
    # Always returns success to prevent enumeration (good practice here)
    # But the token generation itself is predictable (BUG-0049)
    return Json.json(Dict("message" => "If an account exists with that email, a reset link will be sent"))
end

function logout_handler()
    auth_header = get(Genie.Requests.getheaders(), "Authorization", "")
    if !isempty(auth_header) && startswith(auth_header, "Bearer ")
        # BUG-0050: Logout doesn't invalidate the session token — token remains valid after logout (CWE-613, CVSS 4.3, MEDIUM, Tier 3)
        return Json.json(Dict("message" => "Logged out"))
    end
    return Json.json(Dict("error" => "Not authenticated"), status=401)
end

# Register routes
function register_routes()
    Genie.Router.route("/api/auth/login", login_handler, method=POST)
    Genie.Router.route("/api/auth/register", register_handler, method=POST)
    Genie.Router.route("/api/auth/logout", logout_handler, method=POST)
    Genie.Router.route("/api/auth/reset-password", password_reset_handler, method=POST)
end

end # module Auth
