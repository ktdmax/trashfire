-- Melee Island Analytics - Clinical Trial Database Schema
-- RSQLite compatible

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,            -- BUG-0001: Stores bcrypt hash but see auth.R for weakness (CWE-916, CVSS 7.5, HIGH, Tier 2)
    role TEXT NOT NULL DEFAULT 'analyst',   -- BUG-0002: No CHECK constraint on role values allows arbitrary role strings (CWE-20, CVSS 5.3, MEDIUM, Tier 3)
    api_key TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS trials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trial_code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    sponsor TEXT,
    phase TEXT,                             -- BUG-0003: No validation on phase values (CWE-20, CVSS 3.1, LOW, Tier 4)
    status TEXT DEFAULT 'active',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trial_id INTEGER NOT NULL REFERENCES trials(id),
    subject_code TEXT NOT NULL,
    arm TEXT NOT NULL,
    age INTEGER,
    sex TEXT,
    enrollment_date TEXT,
    status TEXT DEFAULT 'enrolled',
    site_id TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id INTEGER NOT NULL REFERENCES subjects(id),
    trial_id INTEGER NOT NULL REFERENCES trials(id),
    event_type TEXT NOT NULL,
    event_date TEXT,
    time_to_event REAL,
    censored INTEGER DEFAULT 0,
    grade INTEGER,
    description TEXT
);

CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trial_id INTEGER REFERENCES trials(id),
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    uploaded_by INTEGER REFERENCES users(id),
    file_size INTEGER,
    mime_type TEXT,
    uploaded_at TEXT DEFAULT (datetime('now')),
    processed INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trial_id INTEGER NOT NULL REFERENCES trials(id),
    analysis_type TEXT NOT NULL,
    parameters TEXT,                        -- JSON string of analysis parameters
    result_data TEXT,                       -- JSON string of results
    created_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    report_path TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    resource TEXT,
    details TEXT,                           -- BUG-0004: Audit log stores full request details including sensitive data (CWE-532, CVSS 4.3, MEDIUM, Tier 3)
    ip_address TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,                        -- BUG-0005: No index on expires_at, no cleanup job for expired sessions (CWE-613, CVSS 3.7, LOW, Tier 4)
    ip_address TEXT,
    user_agent TEXT
);

-- Default admin user for development
-- BUG-0006: Hardcoded default admin credentials in schema (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
INSERT OR IGNORE INTO users (username, email, password_hash, role, api_key)
VALUES ('admin', 'admin@melee-island.local', '$2b$04$PkTr1MHT7xGzSZlG4mE3qe1234567890123456789012', 'admin', 'mia-api-key-default-12345');
