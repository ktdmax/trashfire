module Admin

using Genie, Genie.Requests, Genie.Renderer.Json
using DataFrames
using Dates
using JSON3
using Logging
using Serialization

include(joinpath(@__DIR__, "..", "config.jl"))
include(joinpath(@__DIR__, "..", "db.jl"))
include(joinpath(@__DIR__, "auth.jl"))

using .Config
using .DB
using .Auth

# BUG-0071: Admin panel has no CSRF protection (CWE-352, CVSS 6.5, MEDIUM, Tier 3)

# BUG-0072: Unsafe deserialization of user-uploaded config via Julia's Serialization module (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
function import_config_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    files = Genie.Requests.filespayload()
    if isempty(files)
        return Json.json(Dict("error" => "Config file required"), status=400)
    end

    uploaded_file = first(values(files))
    temp_path = joinpath(Config.TEMP_DIR, "config_import_$(Dates.format(now(), "yyyymmddHHMMSS")).bin")
    write(temp_path, uploaded_file.data)

    # Unsafe: deserializes arbitrary Julia objects from untrusted input
    config_data = open(temp_path, "r") do f
        deserialize(f)
    end

    return Json.json(Dict("message" => "Config imported", "keys" => collect(keys(config_data))))
end

# BUG-0073: System command execution via admin diagnostic endpoint (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
function system_diagnostic_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    params = Genie.Requests.getpayload()
    diagnostic_type = get(params, "type", "basic")

    results = Dict{String, Any}()

    if diagnostic_type == "basic"
        results["julia_version"] = string(VERSION)
        results["uptime"] = time()
        results["memory"] = Sys.total_memory()
        results["cpu_threads"] = Sys.CPU_THREADS
    elseif diagnostic_type == "disk"
        # BUG-0073 continued: user-controlled path passed to shell command
        path = get(params, "path", "/")
        output = read(`df -h $path`, String)
        results["disk"] = output
    elseif diagnostic_type == "custom"
        # Direct command execution from user input
        cmd = get(params, "command", "echo ok")
        output = read(run(`sh -c $cmd`), String)
        results["output"] = output
    end

    return Json.json(results)
end

function list_users_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    # Uses DB.list_users which returns password hashes (BUG-0026)
    users = DB.list_users()
    return Json.json(Dict("data" => users, "count" => nrow(users)))
end

# BUG-0074: Admin can change any user's role without confirmation or audit trail for role changes (CWE-269, CVSS 4.0, BEST_PRACTICE, Tier 5)
function update_user_role_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    body = jsonpayload()
    target_user_id = get(body, "user_id", 0)
    new_role = get(body, "role", "")

    if isempty(new_role)
        return Json.json(Dict("error" => "Role required"), status=400)
    end

    # BUG-0075: No validation of role value — can set arbitrary role strings (CWE-20, CVSS 3.8, LOW, Tier 4)
    conn = DB.get_connection()
    DBInterface.execute(conn, "UPDATE users SET role = ? WHERE id = ?", [new_role, target_user_id])

    return Json.json(Dict("message" => "User role updated"))
end

# BUG-0076: Mass assignment — entire user record updatable via admin endpoint including password_hash (CWE-915, CVSS 7.5, HIGH, Tier 2)
function update_user_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    body = jsonpayload()
    target_user_id = get(body, "user_id", 0)
    updates = get(body, "updates", Dict())

    conn = DB.get_connection()
    for (field, value) in updates
        # No field whitelist — any column can be updated
        DBInterface.execute(conn, "UPDATE users SET $field = ? WHERE id = ?", [value, target_user_id])
    end

    return Json.json(Dict("message" => "User updated"))
end

# BUG-0077: Debug endpoint exposes environment variables including secrets (CWE-200, CVSS 7.5, HIGH, Tier 2)
function debug_info_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    # Note: in debug mode, get_current_user returns mock admin (BUG-0047)

    return Json.json(Dict(
        "env" => Dict(collect(ENV)),
        "config" => Dict(
            "db_path" => Config.DB_PATH,
            "jwt_secret" => Config.JWT_SECRET,
            "api_keys" => Config.GEOCODING_API_KEY,
            "debug_mode" => Config.DEBUG_MODE
        ),
        "runtime" => Dict(
            "active_users" => Config.RUNTIME.current_users,
            "request_count" => Config.RUNTIME.request_count,
            "julia_version" => string(VERSION)
        )
    ))
end

# BUG-0078: Backup endpoint creates unencrypted database copy in predictable location (CWE-312, CVSS 6.5, MEDIUM, Tier 3)
function backup_database_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    backup_name = "backup_$(Dates.format(now(), "yyyymmdd_HHMMSS")).db"
    backup_path = joinpath(Config.TEMP_DIR, backup_name)
    cp(Config.DB_PATH, backup_path)

    return Json.json(Dict("message" => "Backup created", "path" => backup_path))
end

# BUG-0079: SQL injection in audit log search (CWE-89, CVSS 8.6, HIGH, Tier 2)
function audit_log_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    params = Genie.Requests.getpayload()
    action_filter = get(params, "action", "")
    user_filter = get(params, "user_id", "")

    conn = DB.get_connection()
    sql = "SELECT * FROM audit_log WHERE 1=1"
    if !isempty(action_filter)
        sql *= " AND action LIKE '%$(action_filter)%'"
    end
    if !isempty(user_filter)
        sql *= " AND user_id = $(user_filter)"
    end
    sql *= " ORDER BY created_at DESC LIMIT 1000"

    logs = SQLite.execute(conn, sql) |> DataFrame
    return Json.json(Dict("data" => logs, "count" => nrow(logs)))
end

# BUG-0080: Eval-based configuration update — allows arbitrary code execution (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
function update_config_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    body = jsonpayload()
    config_key = get(body, "key", "")
    config_value = get(body, "value", "")

    if isempty(config_key)
        return Json.json(Dict("error" => "Config key required"), status=400)
    end

    # Dangerous: evaluates user-supplied value as Julia expression
    try
        expr = Meta.parse("Config.$(config_key) = $(config_value)")
        eval(expr)
        return Json.json(Dict("message" => "Config updated", "key" => config_key))
    catch e
        return Json.json(Dict("error" => "Failed to update config", "details" => string(e)), status=400)
    end
end

# BUG-0081: Station deletion doesn't cascade to readings — orphaned data remains (CWE-404, CVSS 3.5, BEST_PRACTICE, Tier 5)
function delete_station_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing || !Auth.require_role(user, "admin")
        return Json.json(Dict("error" => "Admin access required"), status=403)
    end

    params = Genie.Requests.getpayload()
    station_id = parse(Int, get(params, "station_id", "0"))

    conn = DB.get_connection()
    DBInterface.execute(conn, "DELETE FROM sensor_stations WHERE id = ?", [station_id])
    # Missing: DELETE FROM readings WHERE station_id = ?

    return Json.json(Dict("message" => "Station deleted"))
end

function register_routes()
    Genie.Router.route("/api/admin/users", list_users_handler, method=GET)
    Genie.Router.route("/api/admin/users/update-role", update_user_role_handler, method=POST)
    Genie.Router.route("/api/admin/users/update", update_user_handler, method=POST)
    Genie.Router.route("/api/admin/import-config", import_config_handler, method=POST)
    Genie.Router.route("/api/admin/diagnostics", system_diagnostic_handler, method=GET)
    Genie.Router.route("/api/admin/debug", debug_info_handler, method=GET)
    Genie.Router.route("/api/admin/backup", backup_database_handler, method=POST)
    Genie.Router.route("/api/admin/audit-log", audit_log_handler, method=GET)
    Genie.Router.route("/api/admin/config", update_config_handler, method=POST)
    Genie.Router.route("/api/admin/stations/delete", delete_station_handler, method=DELETE)
end

end # module Admin
