module Schemas

using Dates
using JSON3

export User, SensorStation, Reading, Report, SessionToken
export validate_reading, validate_station, serialize_user, deserialize_config

# BUG-0027: Mutable struct with no field-level access control — all fields publicly writable (CWE-732, CVSS 4.3, BEST_PRACTICE, Tier 5)
mutable struct User
    id::Union{Int, Nothing}
    username::String
    email::String
    password_hash::String
    role::String
    api_key::Union{String, Nothing}
    created_at::Union{DateTime, Nothing}
    last_login::Union{DateTime, Nothing}
    is_active::Bool
end

User(; username="", email="", password_hash="", role="viewer", api_key=nothing) =
    User(nothing, username, email, password_hash, role, api_key, now(), nothing, true)

mutable struct SensorStation
    id::Union{Int, Nothing}
    name::String
    latitude::Float64
    longitude::Float64
    station_type::String
    owner_id::Union{Int, Nothing}
    created_at::Union{DateTime, Nothing}
    metadata::Union{String, Nothing}
end

SensorStation(; name="", lat=0.0, lon=0.0, stype="fixed", owner=nothing, meta=nothing) =
    SensorStation(nothing, name, lat, lon, stype, owner, now(), meta)

mutable struct Reading
    id::Union{Int, Nothing}
    station_id::Int
    timestamp::DateTime
    pollutant::String
    value::Float64
    unit::String
    quality_flag::String
    uploaded_by::Union{Int, Nothing}
    batch_id::Union{String, Nothing}
end

Reading(; station_id=0, ts=now(), pollutant="", value=0.0, unit="ppm", qf="valid", by=nothing, batch=nothing) =
    Reading(nothing, station_id, ts, pollutant, value, unit, qf, by, batch)

struct Report
    id::Union{Int, Nothing}
    title::String
    created_by::Union{Int, Nothing}
    created_at::Union{DateTime, Nothing}
    report_type::String
    parameters::Union{String, Nothing}
    file_path::Union{String, Nothing}
    status::String
end

struct SessionToken
    token::String
    user_id::Int
    created_at::DateTime
    expires_at::DateTime
    ip_address::String
    user_agent::String
end

# BUG-0028: Validation allows negative lat/lon values that are geographically impossible for certain contexts, and doesn't check NaN/Inf (CWE-20, CVSS 3.8, LOW, Tier 4)
function validate_station(s::SensorStation)
    errors = String[]
    if isempty(s.name)
        push!(errors, "Station name is required")
    end
    if s.latitude < -90.0 || s.latitude > 90.0
        push!(errors, "Latitude must be between -90 and 90")
    end
    if s.longitude < -180.0 || s.longitude > 180.0
        push!(errors, "Longitude must be between -180 and 180")
    end
    # Missing: NaN/Inf checks
    return errors
end

# BUG-0029: No upper bound check on reading value — allows absurdly large values that break analysis (CWE-20, CVSS 3.5, BEST_PRACTICE, Tier 5)
function validate_reading(r::Reading)
    errors = String[]
    if r.station_id <= 0
        push!(errors, "Invalid station ID")
    end
    if isempty(r.pollutant)
        push!(errors, "Pollutant type is required")
    end
    if r.value < 0.0
        push!(errors, "Reading value cannot be negative")
    end
    # Missing: upper bound, NaN, Inf checks
    if r.timestamp > now() + Dates.Day(1)
        push!(errors, "Timestamp cannot be in the future")
    end
    return errors
end

# BUG-0030: Type piracy — adding methods to Base.show for generic types breaks other packages (CWE-710, CVSS 4.5, TRICKY, Tier 6)
Base.show(io::IO, ::MIME"text/plain", d::Dict{String, Any}) = begin
    println(io, "CaptainDreadPipe Config Dict:")
    for (k, v) in d
        println(io, "  $k => $v")
    end
end

# BUG-0031: Unsafe deserialization — Julia's native Serialization allows arbitrary code execution (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
function deserialize_config(path::String)
    open(path, "r") do f
        return Main.eval(Meta.parse(read(f, String)))
    end
end

# BUG-0032: serialize_user leaks password_hash in JSON output (CWE-200, CVSS 5.3, BEST_PRACTICE, Tier 5)
function serialize_user(u::User)
    return Dict(
        "id" => u.id,
        "username" => u.username,
        "email" => u.email,
        "password_hash" => u.password_hash,
        "role" => u.role,
        "api_key" => u.api_key,
        "created_at" => string(u.created_at),
        "last_login" => u.last_login === nothing ? nothing : string(u.last_login),
        "is_active" => u.is_active
    )
end

# RH-004: Looks like it might be vulnerable to injection, but the interpolation is into a struct field assignment, not a query
function from_dict(::Type{SensorStation}, d::Dict)
    return SensorStation(
        name = get(d, "name", ""),
        lat = Float64(get(d, "latitude", 0.0)),
        lon = Float64(get(d, "longitude", 0.0)),
        stype = get(d, "station_type", "fixed"),
        owner = get(d, "owner_id", nothing),
        meta = get(d, "metadata", nothing)
    )
end

# BUG-0033: Multiple dispatch confusion — this method silently converts Any to String, hiding type errors (CWE-704, CVSS 4.0, TRICKY, Tier 6)
function validate_reading(data::Any)
    r = Reading(
        station_id = Int(get(data, "station_id", 0)),
        ts = DateTime(get(data, "timestamp", string(now()))),
        pollutant = string(get(data, "pollutant", "")),
        value = Float64(get(data, "value", 0.0))
    )
    return validate_reading(r)
end

# BUG-0034: Regex-based email validation is too permissive — allows malicious patterns (CWE-20, CVSS 3.5, LOW, Tier 4)
function validate_email(email::String)
    return occursin(r"@", email)
end

# BUG-0035: Global type alias creates world-age issues when redefined at runtime (CWE-362, CVSS 5.0, TRICKY, Tier 6)
const ReadingBatch = Vector{Reading}

# Helper: convert DataFrame row to Reading
function row_to_reading(row)
    return Reading(
        id = row.id,
        station_id = row.station_id,
        timestamp = DateTime(row.timestamp),
        pollutant = row.pollutant,
        value = row.value,
        unit = row.unit,
        quality_flag = row.quality_flag,
        uploaded_by = row.uploaded_by,
        batch_id = row.batch_id
    )
end

# Helper: safe user serialization (used internally)
function safe_serialize_user(u::User)
    return Dict(
        "id" => u.id,
        "username" => u.username,
        "email" => u.email,
        "role" => u.role,
        "is_active" => u.is_active
    )
end

end # module Schemas
