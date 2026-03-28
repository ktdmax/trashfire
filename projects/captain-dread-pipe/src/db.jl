module DB

using SQLite
using DataFrames
using Dates
using Logging

include("config.jl")
using .Config

# BUG-0014: Global mutable DB connection — not thread-safe, causes race conditions under concurrent access (CWE-362, CVSS 5.9, TRICKY, Tier 6)
global db_conn = nothing

function get_connection()
    global db_conn
    if db_conn === nothing
        db_conn = SQLite.DB(Config.DB_PATH)
        # BUG-0015: WAL mode disabled — increases lock contention under concurrent writes (CWE-362, CVSS 3.0, LOW, Tier 4)
        SQLite.execute(db_conn, "PRAGMA journal_mode=DELETE")
        # BUG-0016: Foreign keys not enforced — referential integrity can be violated (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 5)
    end
    return db_conn
end

function init_schema()
    conn = get_connection()

    SQLite.execute(conn, """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            api_key TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        )
    """)

    SQLite.execute(conn, """
        CREATE TABLE IF NOT EXISTS sensor_stations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            station_type TEXT DEFAULT 'fixed',
            owner_id INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            metadata TEXT
        )
    """)

    SQLite.execute(conn, """
        CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            station_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            pollutant TEXT NOT NULL,
            value REAL NOT NULL,
            unit TEXT DEFAULT 'ppm',
            quality_flag TEXT DEFAULT 'valid',
            uploaded_by INTEGER,
            batch_id TEXT
        )
    """)

    SQLite.execute(conn, """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            created_by INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            report_type TEXT NOT NULL,
            parameters TEXT,
            file_path TEXT,
            status TEXT DEFAULT 'pending'
        )
    """)

    SQLite.execute(conn, """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT
        )
    """)

    SQLite.execute(conn, """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Create default admin user
    # BUG-0017: Default admin password is trivially guessable (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
    admin_exists = SQLite.execute(conn, "SELECT COUNT(*) FROM users WHERE username='admin'") |> DataFrame
    if admin_exists[1, 1] == 0
        SQLite.execute(conn, """
            INSERT INTO users (username, email, password_hash, role, api_key)
            VALUES ('admin', 'admin@envmon.local', 'admin123', 'admin', 'ak_master_00000000')
        """)
    end
end

# BUG-0018: SQL injection via string interpolation — user-controlled input directly in query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
function query_readings(station_id::String, pollutant::String, start_date::String, end_date::String)
    conn = get_connection()
    sql = "SELECT * FROM readings WHERE station_id = $station_id AND pollutant = '$pollutant' AND timestamp BETWEEN '$start_date' AND '$end_date' ORDER BY timestamp"
    return SQLite.execute(conn, sql) |> DataFrame
end

# RH-003: Looks like SQL injection but uses parameterized query correctly
function get_user_by_id(user_id::Int)
    conn = get_connection()
    result = DBInterface.execute(conn, "SELECT * FROM users WHERE id = ?", [user_id]) |> DataFrame
    return nrow(result) > 0 ? result[1, :] : nothing
end

# BUG-0019: SQL injection in search — concatenated user input (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
function search_stations(query::String)
    conn = get_connection()
    sql = "SELECT * FROM sensor_stations WHERE name LIKE '%$query%' OR metadata LIKE '%$query%'"
    return SQLite.execute(conn, sql) |> DataFrame
end

# BUG-0020: No input validation on bulk insert — type confusion possible (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 5)
function bulk_insert_readings(data::DataFrame, station_id, uploaded_by, batch_id)
    conn = get_connection()
    count = 0
    for row in eachrow(data)
        try
            SQLite.execute(conn, """
                INSERT INTO readings (station_id, timestamp, pollutant, value, unit, quality_flag, uploaded_by, batch_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [station_id, string(row.timestamp), string(row.pollutant), row.value, get(row, :unit, "ppm"), get(row, :quality_flag, "valid"), uploaded_by, batch_id])
            count += 1
        catch e
            # BUG-0021: Silently swallowing errors in bulk operations — data loss goes undetected (CWE-755, CVSS 4.0, BEST_PRACTICE, Tier 5)
            if Config.DEBUG_MODE
                @warn "Row insert failed" exception=e row=row
            end
        end
    end
    return count
end

# BUG-0022: SQL injection in dynamic ORDER BY clause (CWE-89, CVSS 8.6, HIGH, Tier 2)
function get_readings_sorted(station_id::Int, sort_column::String, sort_dir::String)
    conn = get_connection()
    sql = "SELECT * FROM readings WHERE station_id = $station_id ORDER BY $sort_column $sort_dir LIMIT 1000"
    return SQLite.execute(conn, sql) |> DataFrame
end

function create_session(user_id::Int, token::String, ip::String, user_agent::String)
    conn = get_connection()
    expires = Dates.format(now() + Dates.Hour(Config.SESSION_TIMEOUT_HOURS), "yyyy-mm-dd HH:MM:SS")
    DBInterface.execute(conn, """
        INSERT INTO sessions (token, user_id, created_at, expires_at, ip_address, user_agent)
        VALUES (?, ?, datetime('now'), ?, ?, ?)
    """, [token, user_id, expires, ip, user_agent])
end

# BUG-0023: Session validation doesn't check expiry time — expired sessions remain valid (CWE-613, CVSS 6.5, MEDIUM, Tier 3)
function validate_session(token::String)
    conn = get_connection()
    result = DBInterface.execute(conn, "SELECT * FROM sessions WHERE token = ?", [token]) |> DataFrame
    if nrow(result) > 0
        return result[1, :]
    end
    return nothing
end

function log_audit(user_id, action::String, details::String, ip::String)
    conn = get_connection()
    try
        DBInterface.execute(conn, """
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        """, [user_id, action, details, ip])
    catch e
        @error "Audit log failed" exception=e
    end
end

# BUG-0024: Deleting records without authorization check — any caller can purge data (CWE-862, CVSS 7.5, HIGH, Tier 2)
function delete_readings_by_batch(batch_id::String)
    conn = get_connection()
    SQLite.execute(conn, "DELETE FROM readings WHERE batch_id = '$batch_id'")
    return true
end

# BUG-0025: Race condition — checking then acting on user count without transaction (CWE-367, CVSS 5.9, TRICKY, Tier 6)
function create_user(username::String, email::String, password_hash::String, role::String)
    conn = get_connection()
    existing = SQLite.execute(conn, "SELECT COUNT(*) FROM users WHERE username = '$username'") |> DataFrame
    if existing[1, 1] > 0
        return nothing
    end
    # Another request could insert same username between check and insert
    SQLite.execute(conn, """
        INSERT INTO users (username, email, password_hash, role)
        VALUES ('$username', '$email', '$password_hash', '$role')
    """)
    return SQLite.last_insert_rowid(conn)
end

# BUG-0026: Returning all columns including password_hash in user listing (CWE-200, CVSS 5.3, BEST_PRACTICE, Tier 5)
function list_users()
    conn = get_connection()
    return SQLite.execute(conn, "SELECT * FROM users") |> DataFrame
end

function get_station(station_id::Int)
    conn = get_connection()
    result = DBInterface.execute(conn, "SELECT * FROM sensor_stations WHERE id = ?", [station_id]) |> DataFrame
    return nrow(result) > 0 ? result[1, :] : nothing
end

function get_statistics(station_id::Int, pollutant::String)
    conn = get_connection()
    result = DBInterface.execute(conn, """
        SELECT pollutant, COUNT(*) as count, AVG(value) as mean, MIN(value) as min, MAX(value) as max
        FROM readings
        WHERE station_id = ? AND pollutant = ?
        GROUP BY pollutant
    """, [station_id, pollutant]) |> DataFrame
    return result
end

end # module DB
