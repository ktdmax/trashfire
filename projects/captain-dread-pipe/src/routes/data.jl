module DataRoutes

using Genie, Genie.Requests, Genie.Renderer.Json
using CSV
using DataFrames
using Dates
using JSON3
using Logging
using UUIDs

include(joinpath(@__DIR__, "..", "config.jl"))
include(joinpath(@__DIR__, "..", "db.jl"))
include(joinpath(@__DIR__, "auth.jl"))

using .Config
using .DB
using .Auth

# BUG-0051: Path traversal in file upload — user-controlled filename used directly (CWE-22, CVSS 8.6, HIGH, Tier 2)
function upload_csv_handler()
    try
        user = Auth.get_current_user(Genie.Requests.getpayload())
        if user === nothing
            return Json.json(Dict("error" => "Authentication required"), status=401)
        end

        files = Genie.Requests.filespayload()
        if isempty(files)
            return Json.json(Dict("error" => "No file uploaded"), status=400)
        end

        uploaded_file = first(values(files))
        filename = uploaded_file.name
        # BUG-0051 continued: no sanitization of filename — allows ../../../etc/passwd style paths
        filepath = joinpath(Config.UPLOAD_DIR, filename)

        # BUG-0052: No file type validation — accepts any file regardless of extension or content (CWE-434, CVSS 7.5, HIGH, Tier 2)
        write(filepath, uploaded_file.data)

        # BUG-0053: No file size check before writing — can exhaust disk space (CWE-400, CVSS 4.3, BEST_PRACTICE, Tier 5)
        station_id = get(Genie.Requests.getpayload(), "station_id", "0")
        batch_id = string(uuid4())

        # Parse CSV
        df = CSV.read(filepath, DataFrame)

        # BUG-0054: No validation of CSV column names — Meta.parse used to dynamically access columns (CWE-94, CVSS 9.0, CRITICAL, Tier 1)
        column_mapping = get(Genie.Requests.getpayload(), "column_mapping", "")
        if !isempty(column_mapping)
            mapping = JSON3.read(column_mapping)
            for (src, dst) in pairs(mapping)
                expr = Meta.parse("df.:$src")
                rename!(df, eval(expr) => Symbol(dst))
            end
        end

        user_id = user isa Dict ? user["id"] : user.id
        count = DB.bulk_insert_readings(df, parse(Int, station_id), user_id, batch_id)

        DB.log_audit(user_id, "upload", "Uploaded $filename ($count readings, batch: $batch_id)", string(Genie.Requests.getip()))
        return Json.json(Dict("message" => "Upload successful", "count" => count, "batch_id" => batch_id))
    catch e
        @error "Upload failed" exception=e
        return Json.json(Dict("error" => "Upload failed", "details" => string(e)), status=500)
    end
end

# BUG-0055: IDOR — any authenticated user can query any station's data without ownership check (CWE-639, CVSS 6.5, TRICKY, Tier 6)
function query_readings_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end

    params = Genie.Requests.getpayload()
    station_id = get(params, "station_id", "")
    pollutant = get(params, "pollutant", "")
    start_date = get(params, "start_date", "")
    end_date = get(params, "end_date", "")

    if isempty(station_id)
        return Json.json(Dict("error" => "station_id is required"), status=400)
    end

    # Uses the SQL-injectable DB.query_readings (BUG-0018)
    readings = DB.query_readings(station_id, pollutant, start_date, end_date)
    return Json.json(Dict("data" => readings, "count" => nrow(readings)))
end

function search_stations_handler()
    params = Genie.Requests.getpayload()
    query = get(params, "q", "")

    if isempty(query)
        return Json.json(Dict("error" => "Search query required"), status=400)
    end

    # Uses the SQL-injectable DB.search_stations (BUG-0019)
    stations = DB.search_stations(query)
    return Json.json(Dict("data" => stations, "count" => nrow(stations)))
end

# BUG-0056: Command injection via station export — user input passed to shell command (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
function export_station_data_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end

    params = Genie.Requests.getpayload()
    station_id = get(params, "station_id", "")
    format = get(params, "format", "csv")
    output_name = get(params, "filename", "export_$(station_id)")

    # Command injection: output_name comes from user input
    export_path = joinpath(Config.TEMP_DIR, "$(output_name).$(format)")
    if format == "csv"
        readings = DB.query_readings(station_id, "", "1970-01-01", "2099-12-31")
        CSV.write(export_path, readings)
    elseif format == "compressed"
        csv_path = joinpath(Config.TEMP_DIR, "$(output_name).csv")
        readings = DB.query_readings(station_id, "", "1970-01-01", "2099-12-31")
        CSV.write(csv_path, readings)
        # BUG-0056 continued: shell injection via run()
        run(`tar czf $(export_path).tar.gz -C $(Config.TEMP_DIR) $(output_name).csv`)
    end

    return Json.json(Dict("file" => export_path, "message" => "Export complete"))
end

# BUG-0057: Dynamic code evaluation from user-supplied filter expression (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
function filter_readings_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end

    params = Genie.Requests.getpayload()
    station_id = parse(Int, get(params, "station_id", "0"))
    filter_expr = get(params, "filter", "")

    conn = DB.get_connection()
    readings = DBInterface.execute(conn, "SELECT * FROM readings WHERE station_id = ?", [station_id]) |> DataFrame

    if !isempty(filter_expr)
        # User-supplied Julia expression evaluated directly
        filter_fn = eval(Meta.parse("row -> $(filter_expr)"))
        readings = filter(filter_fn, eachrow(readings)) |> DataFrame
    end

    return Json.json(Dict("data" => readings, "count" => nrow(readings)))
end

# BUG-0058: No pagination — returns all readings, potential DoS via memory exhaustion (CWE-400, CVSS 3.5, LOW, Tier 4)
function list_all_readings_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end

    conn = DB.get_connection()
    readings = SQLite.execute(conn, "SELECT * FROM readings") |> DataFrame
    return Json.json(Dict("data" => readings, "count" => nrow(readings)))
end

# BUG-0059: Race condition in batch delete — TOCTOU between existence check and deletion (CWE-367, CVSS 5.9, TRICKY, Tier 6)
function delete_batch_handler()
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end

    params = Genie.Requests.getpayload()
    batch_id = get(params, "batch_id", "")

    if isempty(batch_id)
        return Json.json(Dict("error" => "batch_id required"), status=400)
    end

    # Check if batch exists (TOCTOU gap here)
    conn = DB.get_connection()
    existing = DBInterface.execute(conn, "SELECT COUNT(*) as cnt FROM readings WHERE batch_id = ?", [batch_id]) |> DataFrame
    if existing[1, :cnt] == 0
        return Json.json(Dict("error" => "Batch not found"), status=404)
    end

    # Another request could modify or delete between check and action
    DB.delete_readings_by_batch(batch_id)
    return Json.json(Dict("message" => "Batch deleted", "batch_id" => batch_id))
end

# BUG-0060: Unrestricted file download — path traversal in download endpoint (CWE-22, CVSS 7.5, HIGH, Tier 2)
function download_export_handler()
    params = Genie.Requests.getpayload()
    filename = get(params, "file", "")

    if isempty(filename)
        return Json.json(Dict("error" => "Filename required"), status=400)
    end

    # No sanitization — allows ../../etc/passwd
    filepath = joinpath(Config.TEMP_DIR, filename)

    if !isfile(filepath)
        return Json.json(Dict("error" => "File not found"), status=404)
    end

    return Genie.Renderer.respond(read(filepath), "application/octet-stream")
end

# RH-005: Looks like it might be vulnerable to injection via sort parameter, but uses a whitelist
function sorted_readings_handler()
    params = Genie.Requests.getpayload()
    station_id = parse(Int, get(params, "station_id", "0"))
    sort_col = get(params, "sort", "timestamp")
    sort_dir = get(params, "dir", "ASC")

    allowed_cols = ["timestamp", "value", "pollutant", "quality_flag"]
    allowed_dirs = ["ASC", "DESC"]

    if !(sort_col in allowed_cols)
        sort_col = "timestamp"
    end
    if !(uppercase(sort_dir) in allowed_dirs)
        sort_dir = "ASC"
    end

    conn = DB.get_connection()
    result = DBInterface.execute(conn, "SELECT * FROM readings WHERE station_id = ? ORDER BY $sort_col $sort_dir LIMIT 500", [station_id]) |> DataFrame
    return Json.json(Dict("data" => result))
end

# BUG-0061: Bulk update endpoint with no authorization check — any user can update any reading (CWE-862, CVSS 7.5, HIGH, Tier 2)
function bulk_update_handler()
    body = jsonpayload()
    updates = get(body, "updates", [])

    conn = DB.get_connection()
    updated = 0
    for u in updates
        reading_id = u["id"]
        new_value = u["value"]
        # No auth check, no ownership verification
        DBInterface.execute(conn, "UPDATE readings SET value = ? WHERE id = ?", [new_value, reading_id])
        updated += 1
    end

    return Json.json(Dict("message" => "Updated $updated readings"))
end

# BUG-0062: Type instability in aggregation — return type varies, causes performance degradation and potential errors (CWE-704, CVSS 3.0, BEST_PRACTICE, Tier 5)
function aggregate_handler()
    params = Genie.Requests.getpayload()
    station_id = get(params, "station_id", "0")
    agg_type = get(params, "aggregation", "mean")

    conn = DB.get_connection()
    readings = DBInterface.execute(conn, "SELECT value FROM readings WHERE station_id = ?", [parse(Int, station_id)]) |> DataFrame

    if nrow(readings) == 0
        return Json.json(Dict("result" => nothing))
    end

    values = readings.value
    result = if agg_type == "mean"
        sum(values) / length(values)
    elseif agg_type == "median"
        sort(values)[div(length(values), 2) + 1]
    elseif agg_type == "sum"
        sum(values)
    elseif agg_type == "count"
        length(values)  # Returns Int, not Float64 like others
    else
        "unknown aggregation"  # Returns String — type instability
    end

    return Json.json(Dict("result" => result, "aggregation" => agg_type))
end

function register_routes()
    Genie.Router.route("/api/data/upload", upload_csv_handler, method=POST)
    Genie.Router.route("/api/data/query", query_readings_handler, method=GET)
    Genie.Router.route("/api/data/search", search_stations_handler, method=GET)
    Genie.Router.route("/api/data/export", export_station_data_handler, method=GET)
    Genie.Router.route("/api/data/filter", filter_readings_handler, method=GET)
    Genie.Router.route("/api/data/all", list_all_readings_handler, method=GET)
    Genie.Router.route("/api/data/batch/delete", delete_batch_handler, method=DELETE)
    Genie.Router.route("/api/data/download", download_export_handler, method=GET)
    Genie.Router.route("/api/data/sorted", sorted_readings_handler, method=GET)
    Genie.Router.route("/api/data/bulk-update", bulk_update_handler, method=POST)
    Genie.Router.route("/api/data/aggregate", aggregate_handler, method=GET)
end

end # module DataRoutes
