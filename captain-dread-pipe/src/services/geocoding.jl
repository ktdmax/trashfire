module Geocoding

using HTTP
using JSON3
using Dates
using Logging

include(joinpath(@__DIR__, "..", "config.jl"))
include(joinpath(@__DIR__, "..", "db.jl"))

using .Config
using .DB

# BUG-0092: SSRF — user-controlled URL parameter used to make server-side HTTP requests (CWE-918, CVSS 7.5, HIGH, Tier 2)
function geocode_address(address::String; api_url::String=Config.GEOCODING_API_URL)
    # api_url can be overridden by caller — allows SSRF to internal services
    encoded = HTTP.escapeuri(address)
    url = "$(api_url)/geocode?address=$(encoded)&key=$(Config.GEOCODING_API_KEY)"

    try
        response = HTTP.get(url; connect_timeout=10, readtimeout=30)
        data = JSON3.read(String(response.body))
        if haskey(data, :results) && length(data.results) > 0
            loc = data.results[1].geometry.location
            return Dict("latitude" => loc.lat, "longitude" => loc.lng, "formatted" => data.results[1].formatted_address)
        end
        return Dict("error" => "No results found")
    catch e
        # BUG-0093: Error message leaks internal URL and API key (CWE-209, CVSS 4.3, MEDIUM, Tier 3)
        return Dict("error" => "Geocoding failed: $(string(e)) | URL: $url")
    end
end

# BUG-0094: SSRF via webhook URL — user can specify arbitrary internal URLs for notifications (CWE-918, CVSS 7.5, HIGH, Tier 2)
function send_alert_notification(station_id::Int, pollutant::String, value::Float64, threshold::Float64;
                                  webhook_url::String=Config.NOTIFICATION_WEBHOOK_URL)
    payload = JSON3.write(Dict(
        "station_id" => station_id,
        "pollutant" => pollutant,
        "value" => value,
        "threshold" => threshold,
        "exceeded_by" => value - threshold,
        "timestamp" => string(now()),
        "severity" => value > threshold * 2 ? "critical" : "warning"
    ))

    try
        # webhook_url from user input — can target internal services
        response = HTTP.post(webhook_url;
            headers=["Content-Type" => "application/json"],
            body=payload,
            connect_timeout=5,
            readtimeout=10
        )
        return Dict("status" => "sent", "response_code" => response.status)
    catch e
        @error "Alert notification failed" exception=e
        return Dict("status" => "failed", "error" => string(e))
    end
end

# BUG-0095: Reverse geocoding with XML response parsing — XXE injection possible if external API returns crafted XML (CWE-611, CVSS 6.5, MEDIUM, Tier 3)
function reverse_geocode(lat::Float64, lon::Float64; format::String="json")
    url = "$(Config.GEOCODING_API_URL)/reverse?lat=$(lat)&lon=$(lon)&format=$(format)&key=$(Config.GEOCODING_API_KEY)"

    try
        response = HTTP.get(url; connect_timeout=10, readtimeout=30)
        body = String(response.body)

        if format == "xml"
            # Naively processes XML response without disabling external entities
            # If the geocoding API returns crafted XML, XXE is possible
            return Dict("raw" => body, "format" => "xml")
        else
            data = JSON3.read(body)
            return Dict("address" => get(data, :address, "Unknown"), "data" => data)
        end
    catch e
        return Dict("error" => "Reverse geocoding failed: $(string(e))")
    end
end

# BUG-0096: Batch geocoding with no rate limiting — can overwhelm external API (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
function batch_geocode_stations()
    conn = DB.get_connection()
    stations = SQLite.execute(conn, "SELECT * FROM sensor_stations WHERE metadata IS NULL OR metadata = ''") |> DataFrames.DataFrame

    results = Dict{Int, Any}()
    for row in eachrow(stations)
        # No rate limiting between requests
        result = reverse_geocode(row.latitude, row.longitude)
        results[row.id] = result

        if haskey(result, "address")
            meta = JSON3.write(Dict("address" => result["address"]))
            DBInterface.execute(conn, "UPDATE sensor_stations SET metadata = ? WHERE id = ?", [meta, row.id])
        end
    end

    return results
end

# BUG-0097: Proxy endpoint allows fetching arbitrary URLs — full SSRF (CWE-918, CVSS 8.6, HIGH, Tier 2)
function fetch_external_data(url::String, headers::Dict{String, String}=Dict{String, String}())
    # No URL validation — can access internal networks, cloud metadata, etc.
    try
        h = ["User-Agent" => "CaptainDreadPipe/$(Config.APP_VERSION)"]
        for (k, v) in headers
            push!(h, k => v)
        end
        response = HTTP.get(url; headers=h, connect_timeout=10, readtimeout=30)
        return Dict(
            "status" => response.status,
            "body" => String(response.body),
            "headers" => Dict(response.headers)
        )
    catch e
        return Dict("error" => "Fetch failed: $(string(e))")
    end
end

function compute_distance(lat1::Float64, lon1::Float64, lat2::Float64, lon2::Float64)
    # Haversine formula
    R = 6371.0  # Earth radius in km
    dlat = deg2rad(lat2 - lat1)
    dlon = deg2rad(lon2 - lon1)
    a = sin(dlat/2)^2 + cos(deg2rad(lat1)) * cos(deg2rad(lat2)) * sin(dlon/2)^2
    c = 2 * atan(sqrt(a), sqrt(1-a))
    return R * c
end

function find_nearest_stations(lat::Float64, lon::Float64; limit::Int=5)
    conn = DB.get_connection()
    stations = SQLite.execute(conn, "SELECT * FROM sensor_stations") |> DataFrames.DataFrame

    if nrow(stations) == 0
        return []
    end

    distances = [(row.id, row.name, compute_distance(lat, lon, row.latitude, row.longitude)) for row in eachrow(stations)]
    sort!(distances, by=x -> x[3])

    return [Dict("id" => d[1], "name" => d[2], "distance_km" => round(d[3], digits=2)) for d in distances[1:min(limit, length(distances))]]
end

# BUG-0098: Open redirect — user-controlled redirect URL after geocoding callback (CWE-601, CVSS 4.7, MEDIUM, Tier 3)
function geocoding_callback_url(station_id::Int, redirect_to::String)
    # No validation of redirect_to — can redirect to malicious sites
    return "$(Config.GEOCODING_API_URL)/callback?station=$(station_id)&redirect=$(HTTP.escapeuri(redirect_to))"
end

function update_station_coordinates(station_id::Int, address::String)
    result = geocode_address(address)

    if haskey(result, "latitude")
        conn = DB.get_connection()
        DBInterface.execute(conn, "UPDATE sensor_stations SET latitude = ?, longitude = ? WHERE id = ?",
            [result["latitude"], result["longitude"], station_id])
        return Dict("message" => "Station coordinates updated", "coordinates" => result)
    end

    return Dict("error" => "Could not geocode address")
end

end # module Geocoding
