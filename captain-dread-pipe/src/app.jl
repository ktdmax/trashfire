module CaptainDreadPipe

using Genie
using Genie.Router
using Genie.Renderer.Json
using Genie.Requests
using Dates
using Logging
using JSON3

include("config.jl")
include("db.jl")
include("models/schemas.jl")
include("routes/auth.jl")
include("routes/data.jl")
include("routes/reports.jl")
include("routes/admin.jl")
include("services/analysis.jl")
include("services/geocoding.jl")

using .Config
using .DB
using .Schemas
using .Auth
using .DataRoutes
using .Reports
using .Admin
using .Analysis
using .Geocoding

# BUG-0099: Missing security headers middleware — no X-Frame-Options, X-Content-Type-Options, CSP (CWE-693, CVSS 5.3, MEDIUM, Tier 3)
function setup_middleware()
    # Only sets CORS, missing all security headers
    Genie.config.cors_headers["Access-Control-Allow-Origin"] = join(Config.CORS_ALLOWED_ORIGINS, ",")
    Genie.config.cors_headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    Genie.config.cors_headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
    Genie.config.cors_allowed_origins = Config.CORS_ALLOWED_ORIGINS
end

# BUG-0100: Request logging middleware logs full request bodies including passwords and tokens (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
function request_logger(handler)
    return function(req)
        Config.RUNTIME.request_count += 1
        push!(Config.RUNTIME.current_users, get(req.headers, "Authorization", "anonymous"))

        # Logs entire request body — includes passwords, tokens, sensitive data
        body_str = try
            String(copy(req.body))
        catch
            "<no body>"
        end

        @info "REQUEST" method=req.method path=req.target ip=req.ip body=body_str headers=req.headers timestamp=now()

        # Write to log file
        open(Config.LOG_FILE, "a") do f
            write(f, "[$(now())] $(req.method) $(req.target) | IP: $(req.ip) | Body: $(body_str)\n")
        end

        return handler(req)
    end
end

# Health check endpoint
route("/api/health") do
    Json.json(Dict(
        "status" => "ok",
        "version" => Config.APP_VERSION,
        "timestamp" => string(now()),
        "debug" => Config.DEBUG_MODE,
        "requests_served" => Config.RUNTIME.request_count
    ))
end

# Root endpoint
route("/") do
    """
    <!DOCTYPE html>
    <html>
    <head><title>$(Config.APP_NAME)</title></head>
    <body>
    <h1>$(Config.APP_NAME) v$(Config.APP_VERSION)</h1>
    <p>Environmental Monitoring Dashboard</p>
    <ul>
        <li><a href="/api/health">Health Check</a></li>
        <li><a href="/api/docs">API Documentation</a></li>
    </ul>
    </body>
    </html>
    """
end

# API documentation endpoint
route("/api/docs") do
    Json.json(Dict(
        "name" => Config.APP_NAME,
        "version" => Config.APP_VERSION,
        "endpoints" => Dict(
            "auth" => ["/api/auth/login", "/api/auth/register", "/api/auth/logout", "/api/auth/reset-password"],
            "data" => ["/api/data/upload", "/api/data/query", "/api/data/search", "/api/data/export",
                      "/api/data/filter", "/api/data/all", "/api/data/batch/delete", "/api/data/download",
                      "/api/data/sorted", "/api/data/bulk-update", "/api/data/aggregate"],
            "reports" => ["/api/reports/create", "/api/reports/view", "/api/reports/custom",
                         "/api/reports/heatmap", "/api/reports/compliance", "/api/reports/list", "/api/reports/delete"],
            "admin" => ["/api/admin/users", "/api/admin/users/update-role", "/api/admin/users/update",
                       "/api/admin/import-config", "/api/admin/diagnostics", "/api/admin/debug",
                       "/api/admin/backup", "/api/admin/audit-log", "/api/admin/config", "/api/admin/stations/delete"],
            "analysis" => ["/api/analysis/trend", "/api/analysis/anomalies", "/api/analysis/correlation",
                          "/api/analysis/summary", "/api/analysis/custom"],
            "geocoding" => ["/api/geo/geocode", "/api/geo/reverse", "/api/geo/nearest", "/api/geo/fetch"]
        )
    ))
end

# Analysis API routes
route("/api/analysis/trend", method=GET) do
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end
    params = Genie.Requests.getpayload()
    station_id = parse(Int, get(params, "station_id", "0"))
    pollutant = get(params, "pollutant", "PM25")
    result = Analysis.analyze_trend(station_id, pollutant)
    return Json.json(result)
end

route("/api/analysis/anomalies", method=GET) do
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end
    params = Genie.Requests.getpayload()
    station_id = parse(Int, get(params, "station_id", "0"))
    pollutant = get(params, "pollutant", "PM25")
    threshold = parse(Float64, get(params, "threshold", "2.0"))
    result = Analysis.detect_anomalies(station_id, pollutant; threshold=threshold)
    return Json.json(result)
end

route("/api/analysis/summary", method=GET) do
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end
    params = Genie.Requests.getpayload()
    station_id = parse(Int, get(params, "station_id", "0"))
    pollutant = get(params, "pollutant", "PM25")
    result = Analysis.compute_summary_statistics(station_id, pollutant)
    return Json.json(result)
end

# Custom aggregation route — exposes BUG-0085
route("/api/analysis/custom", method=POST) do
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end
    body = jsonpayload()
    station_id = get(body, "station_id", 0)
    pollutant = get(body, "pollutant", "PM25")
    agg_fn = get(body, "function", "mean")
    result = Analysis.run_aggregation(station_id, pollutant, agg_fn)
    return Json.json(result)
end

# Geocoding API routes
route("/api/geo/geocode", method=GET) do
    params = Genie.Requests.getpayload()
    address = get(params, "address", "")
    api_url = get(params, "api_url", Config.GEOCODING_API_URL)
    if isempty(address)
        return Json.json(Dict("error" => "Address required"), status=400)
    end
    result = Geocoding.geocode_address(address; api_url=api_url)
    return Json.json(result)
end

route("/api/geo/reverse", method=GET) do
    params = Genie.Requests.getpayload()
    lat = parse(Float64, get(params, "lat", "0.0"))
    lon = parse(Float64, get(params, "lon", "0.0"))
    format = get(params, "format", "json")
    result = Geocoding.reverse_geocode(lat, lon; format=format)
    return Json.json(result)
end

route("/api/geo/nearest", method=GET) do
    params = Genie.Requests.getpayload()
    lat = parse(Float64, get(params, "lat", "0.0"))
    lon = parse(Float64, get(params, "lon", "0.0"))
    limit = parse(Int, get(params, "limit", "5"))
    result = Geocoding.find_nearest_stations(lat, lon; limit=limit)
    return Json.json(Dict("stations" => result))
end

# BUG-0097 exposed via route: arbitrary URL fetch
route("/api/geo/fetch", method=POST) do
    user = Auth.get_current_user(Genie.Requests.getpayload())
    if user === nothing
        return Json.json(Dict("error" => "Authentication required"), status=401)
    end
    body = jsonpayload()
    url = get(body, "url", "")
    headers = get(body, "headers", Dict{String,String}())
    if isempty(url)
        return Json.json(Dict("error" => "URL required"), status=400)
    end
    result = Geocoding.fetch_external_data(url, headers)
    return Json.json(result)
end

function start_server(; host::String="", port::Int=8080)
    Config.init_dirs()
    DB.init_schema()
    setup_middleware()

    Auth.register_routes()
    DataRoutes.register_routes()
    Reports.register_routes()
    Admin.register_routes()

    bind_host = isempty(host) ? Config.get_bind_address() : host

    @info "Starting $(Config.APP_NAME) v$(Config.APP_VERSION)"
    @info "Debug mode: $(Config.DEBUG_MODE)"
    @info "Binding to $(bind_host):$(port)"

    Genie.config.run_as_server = true
    Genie.config.server_host = bind_host
    Genie.config.server_port = port

    up(port, bind_host)
end

# Auto-start if run directly
if abspath(PROGRAM_FILE) == @__FILE__
    start_server()
end

end # module CaptainDreadPipe
