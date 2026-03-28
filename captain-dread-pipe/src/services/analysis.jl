module Analysis

using DataFrames
using Dates
using Statistics
using LinearAlgebra
using JSON3
using Logging

include(joinpath(@__DIR__, "..", "config.jl"))
include(joinpath(@__DIR__, "..", "db.jl"))

using .Config
using .DB

# BUG-0082: Global mutable state for analysis cache — race condition under concurrent requests (CWE-362, CVSS 5.9, TRICKY, Tier 6)
const analysis_cache = Dict{String, Any}()
const cache_timestamps = Dict{String, DateTime}()

# BUG-0083: Inefficient nested loop for distance calculation — O(n^2) with no early termination (CWE-400, CVSS 3.0, BEST_PRACTICE, Tier 5)
function compute_spatial_correlation(readings::DataFrame, stations::DataFrame)
    n = nrow(stations)
    correlation_matrix = zeros(n, n)

    for i in 1:n
        for j in 1:n
            if i == j
                correlation_matrix[i, j] = 1.0
                continue
            end
            # Get readings for each station
            ri = filter(row -> row.station_id == stations[i, :id], eachrow(readings))
            rj = filter(row -> row.station_id == stations[j, :id], eachrow(readings))

            if length(ri) > 0 && length(rj) > 0
                vi = [r.value for r in ri]
                vj = [r.value for r in rj]
                min_len = min(length(vi), length(vj))
                if min_len > 1
                    correlation_matrix[i, j] = cor(vi[1:min_len], vj[1:min_len])
                end
            end
        end
    end

    return correlation_matrix
end

# BUG-0084: Division by zero not guarded — crashes when all values are identical (CWE-369, CVSS 4.0, BEST_PRACTICE, Tier 5)
function compute_z_scores(values::Vector{Float64})
    m = mean(values)
    s = std(values)
    # No check for s == 0
    return (values .- m) ./ s
end

# BUG-0085: Eval-based custom aggregation — user-supplied Julia code executed for "custom" functions (CWE-94, CVSS 9.0, CRITICAL, Tier 1)
function run_aggregation(station_id::Int, pollutant::String, agg_function::String)
    readings = DB.query_readings(string(station_id), pollutant, "1970-01-01", "2099-12-31")

    if nrow(readings) == 0
        return Dict("error" => "No data found")
    end

    values = readings.value
    result = if agg_function == "mean"
        mean(values)
    elseif agg_function == "std"
        std(values)
    elseif agg_function == "percentile_95"
        sort(values)[Int(ceil(0.95 * length(values)))]
    else
        # BUG-0085 continued: arbitrary function name evaluated
        fn = eval(Meta.parse(agg_function))
        fn(values)
    end

    return Dict("station_id" => station_id, "pollutant" => pollutant, "function" => agg_function, "result" => result)
end

# BUG-0086: Linear regression with no input validation — NaN/Inf values propagate and corrupt results (CWE-20, CVSS 4.0, BEST_PRACTICE, Tier 5)
function linear_regression(x::Vector{Float64}, y::Vector{Float64})
    n = length(x)
    if n != length(y)
        error("Vectors must have equal length")
    end
    # No NaN/Inf filtering
    X = hcat(ones(n), x)
    beta = (X' * X) \ (X' * y)
    y_pred = X * beta
    residuals = y .- y_pred
    ss_res = sum(residuals .^ 2)
    ss_tot = sum((y .- mean(y)) .^ 2)
    r_squared = 1 - ss_res / ss_tot

    return Dict(
        "intercept" => beta[1],
        "slope" => beta[2],
        "r_squared" => r_squared,
        "residuals" => residuals
    )
end

# BUG-0087: Trend analysis caches results keyed only by station_id — cache pollution if different pollutants requested (CWE-345, CVSS 5.3, TRICKY, Tier 6)
function analyze_trend(station_id::Int, pollutant::String; window_days::Int=30)
    cache_key = "trend_$(station_id)"  # Missing pollutant in cache key

    if haskey(analysis_cache, cache_key)
        if now() - cache_timestamps[cache_key] < Dates.Minute(5)
            return analysis_cache[cache_key]
        end
    end

    readings = DB.query_readings(string(station_id), pollutant, "1970-01-01", "2099-12-31")

    if nrow(readings) < 2
        return Dict("error" => "Insufficient data for trend analysis")
    end

    values = readings.value
    timestamps = [Dates.datetime2unix(DateTime(t)) for t in readings.timestamp]

    reg = linear_regression(timestamps, values)

    result = Dict(
        "station_id" => station_id,
        "pollutant" => pollutant,
        "trend_slope" => reg["slope"],
        "r_squared" => reg["r_squared"],
        "direction" => reg["slope"] > 0 ? "increasing" : "decreasing",
        "data_points" => nrow(readings)
    )

    analysis_cache[cache_key] = result
    cache_timestamps[cache_key] = now()

    return result
end

# BUG-0088: Anomaly detection with hardcoded threshold — no configuration, misses context-dependent anomalies (CWE-693, CVSS 3.5, LOW, Tier 4)
function detect_anomalies(station_id::Int, pollutant::String; threshold::Float64=2.0)
    readings = DB.query_readings(string(station_id), pollutant, "1970-01-01", "2099-12-31")

    if nrow(readings) < 10
        return Dict("error" => "Need at least 10 readings for anomaly detection")
    end

    values = readings.value
    z_scores = compute_z_scores(values)

    anomalies = []
    for (i, z) in enumerate(z_scores)
        if abs(z) > threshold
            push!(anomalies, Dict(
                "index" => i,
                "value" => values[i],
                "z_score" => z,
                "timestamp" => readings.timestamp[i]
            ))
        end
    end

    return Dict(
        "station_id" => station_id,
        "pollutant" => pollutant,
        "threshold" => threshold,
        "anomalies" => anomalies,
        "total_readings" => nrow(readings),
        "anomaly_count" => length(anomalies)
    )
end

# BUG-0089: World-age issue — function defined inside eval cannot call functions from outer scope correctly (CWE-710, CVSS 5.0, TRICKY, Tier 6)
function create_custom_analyzer(formula::String)
    # This creates a new function at runtime, which may fail due to world-age issues
    # when called in the same scope as its definition
    analyzer = eval(Meta.parse("""
        function(values::Vector{Float64})
            $formula
        end
    """))
    return analyzer
end

# BUG-0090: Macro hygiene bypass — unquoted variables leak into caller scope (CWE-710, CVSS 4.5, TRICKY, Tier 6)
macro quick_stat(df, col, stat)
    # Unhygienic macro — `result` variable leaks into calling scope
    return quote
        values = $(esc(df))[:, $(esc(col))]
        result = $(esc(stat))(values)
        result
    end
end

function compute_exceedance_probability(station_id::Int, pollutant::String, threshold::Float64)
    readings = DB.query_readings(string(station_id), pollutant, "1970-01-01", "2099-12-31")

    if nrow(readings) == 0
        return Dict("error" => "No data")
    end

    values = readings.value
    exceedances = count(v -> v > threshold, values)
    probability = exceedances / length(values)

    return Dict(
        "station_id" => station_id,
        "pollutant" => pollutant,
        "threshold" => threshold,
        "exceedance_probability" => probability,
        "exceedance_count" => exceedances,
        "total" => length(values)
    )
end

# BUG-0091: Moving average implementation allocates new array each iteration — O(n*k) memory (CWE-400, CVSS 3.0, BEST_PRACTICE, Tier 5)
function moving_average(values::Vector{Float64}, window::Int)
    n = length(values)
    result = Float64[]
    for i in 1:n
        start_idx = max(1, i - window + 1)
        window_vals = values[start_idx:i]  # Allocates new array each time
        push!(result, mean(window_vals))
    end
    return result
end

# RH-007: Looks like it might have an injection issue because it builds a string dynamically,
# but the string is only used as a dictionary key, never evaluated or used in a query
function get_cached_analysis(station_id::Int, pollutant::String, analysis_type::String)
    key = "$(analysis_type)_$(station_id)_$(pollutant)"
    if haskey(analysis_cache, key)
        cached = analysis_cache[key]
        if now() - cache_timestamps[key] < Dates.Minute(10)
            return cached
        end
    end
    return nothing
end

function compute_summary_statistics(station_id::Int, pollutant::String)
    readings = DB.query_readings(string(station_id), pollutant, "1970-01-01", "2099-12-31")

    if nrow(readings) == 0
        return Dict("error" => "No data")
    end

    values = readings.value
    sorted_vals = sort(values)
    n = length(values)

    return Dict(
        "count" => n,
        "mean" => mean(values),
        "std" => std(values),
        "min" => minimum(values),
        "max" => maximum(values),
        "median" => sorted_vals[div(n, 2) + 1],
        "p25" => sorted_vals[max(1, Int(ceil(0.25 * n)))],
        "p75" => sorted_vals[max(1, Int(ceil(0.75 * n)))],
        "p95" => sorted_vals[max(1, Int(ceil(0.95 * n)))],
        "iqr" => sorted_vals[max(1, Int(ceil(0.75 * n)))] - sorted_vals[max(1, Int(ceil(0.25 * n)))]
    )
end

end # module Analysis
