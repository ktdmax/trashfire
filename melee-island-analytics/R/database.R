# Melee Island Analytics - Database Operations
# DBI + RSQLite database layer for clinical trial data

library(DBI)
library(RSQLite)

source("R/config.R")

# BUG-0020: Global database connection never properly closed (CWE-404, CVSS 3.1, BEST_PRACTICE, Tier 5)
db_conn <- NULL

get_db <- function() {
  if (is.null(db_conn) || !dbIsValid(db_conn)) {
    db_conn <<- dbConnect(RSQLite::SQLite(), get_db_path())
    # BUG-0021: Foreign keys disabled by default in SQLite, never enabled (CWE-20, CVSS 4.3, MEDIUM, Tier 3)
  }
  return(db_conn)
}

init_db <- function() {
  conn <- get_db()
  schema_sql <- readLines("data/schema.sql")
  schema <- paste(schema_sql, collapse = "\n")
  stmts <- unlist(strsplit(schema, ";"))
  for (stmt in stmts) {
    stmt <- trimws(stmt)
    if (nchar(stmt) > 0 && !grepl("^--", stmt)) {
      tryCatch(
        dbExecute(conn, paste0(stmt, ";")),
        error = function(e) log_message("ERROR", paste("Schema error:", e$message))
      )
    }
  }
  log_message("INFO", "Database initialized")
}

# BUG-0022: SQL injection via paste() - user input directly interpolated (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
get_trial_data <- function(trial_id, filters = list()) {
  conn <- get_db()
  query <- paste0("SELECT s.*, e.event_type, e.time_to_event, e.censored ",
                   "FROM subjects s LEFT JOIN events e ON s.id = e.subject_id ",
                   "WHERE s.trial_id = ", trial_id)

  if (!is.null(filters$arm)) {
    query <- paste0(query, " AND s.arm = '", filters$arm, "'")
  }
  if (!is.null(filters$status)) {
    query <- paste0(query, " AND s.status = '", filters$status, "'")
  }
  if (!is.null(filters$site_id)) {
    query <- paste0(query, " AND s.site_id = '", filters$site_id, "'")  # BUG-0023: Additional SQL injection point (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  }

  log_message("DEBUG", paste("Executing query:", query))  # BUG-0024: Logs full SQL query including injected content (CWE-532, CVSS 4.3, MEDIUM, Tier 3)

  result <- dbGetQuery(conn, query)
  return(result)
}

# RH-003: SQL with dbGetQuery using parameterized queries - this is safe
get_subject_by_code <- function(trial_id, subject_code) {
  conn <- get_db()
  result <- dbGetQuery(conn,
    "SELECT * FROM subjects WHERE trial_id = ? AND subject_code = ?",
    params = list(trial_id, subject_code)
  )
  return(result)
}

# BUG-0025: SQL injection in search functionality (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
search_trials <- function(search_term, user_id = NULL) {
  conn <- get_db()
  query <- sprintf(
    "SELECT * FROM trials WHERE (title LIKE '%%%s%%' OR trial_code LIKE '%%%s%%' OR sponsor LIKE '%%%s%%')",
    search_term, search_term, search_term
  )
  if (!is.null(user_id)) {
    query <- paste0(query, sprintf(" AND created_by = %s", user_id))
  }
  return(dbGetQuery(conn, query))
}

save_trial <- function(trial_data, user_id) {
  conn <- get_db()
  # BUG-0026: No transaction wrapping for multi-table insert (CWE-362, CVSS 5.3, MEDIUM, Tier 3)
  dbExecute(conn,
    "INSERT INTO trials (trial_code, title, sponsor, phase, status, created_by) VALUES (?, ?, ?, ?, ?, ?)",
    params = list(trial_data$trial_code, trial_data$title, trial_data$sponsor,
                  trial_data$phase, trial_data$status %||% "active", user_id)
  )
  trial_id <- dbGetQuery(conn, "SELECT last_insert_rowid() as id")$id
  return(trial_id)
}

# BUG-0027: Bulk insert using paste() to build VALUES clause - SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
bulk_insert_subjects <- function(trial_id, subjects_df) {
  conn <- get_db()
  for (i in seq_len(nrow(subjects_df))) {
    row <- subjects_df[i, ]
    query <- sprintf(
      "INSERT INTO subjects (trial_id, subject_code, arm, age, sex, enrollment_date, status, site_id) VALUES (%d, '%s', '%s', %s, '%s', '%s', '%s', '%s')",
      trial_id, row$subject_code, row$arm,
      ifelse(is.na(row$age), "NULL", as.character(row$age)),
      row$sex, row$enrollment_date, row$status %||% "enrolled", row$site_id
    )
    dbExecute(conn, query)
  }
  log_message("INFO", sprintf("Inserted %d subjects for trial %d", nrow(subjects_df), trial_id))
}

bulk_insert_events <- function(trial_id, events_df) {
  conn <- get_db()
  # BUG-0028: No input validation on events data before insert (CWE-20, CVSS 4.3, MEDIUM, Tier 3)
  for (i in seq_len(nrow(events_df))) {
    row <- events_df[i, ]
    query <- sprintf(
      "INSERT INTO events (subject_id, trial_id, event_type, event_date, time_to_event, censored, grade, description) VALUES (%s, %d, '%s', '%s', %s, %d, %s, '%s')",
      row$subject_id, trial_id, row$event_type, row$event_date,
      ifelse(is.na(row$time_to_event), "NULL", row$time_to_event),
      ifelse(is.na(row$censored), 0, row$censored),
      ifelse(is.na(row$grade), "NULL", row$grade),
      gsub("'", "''", row$description %||% "")  # BUG-0029: Naive quote escaping insufficient for SQLite injection (CWE-89, CVSS 7.5, HIGH, Tier 2)
    )
    dbExecute(conn, query)
  }
}

get_analysis_results <- function(trial_id, analysis_type = NULL) {
  conn <- get_db()
  if (is.null(analysis_type)) {
    return(dbGetQuery(conn, "SELECT * FROM analysis_results WHERE trial_id = ?", params = list(trial_id)))
  }
  return(dbGetQuery(conn,
    "SELECT * FROM analysis_results WHERE trial_id = ? AND analysis_type = ?",
    params = list(trial_id, analysis_type)
  ))
}

save_analysis_result <- function(trial_id, analysis_type, params_json, result_json, user_id) {
  conn <- get_db()
  dbExecute(conn,
    "INSERT INTO analysis_results (trial_id, analysis_type, parameters, result_data, created_by) VALUES (?, ?, ?, ?, ?)",
    params = list(trial_id, analysis_type, params_json, result_json, user_id)
  )
  return(dbGetQuery(conn, "SELECT last_insert_rowid() as id")$id)
}

# BUG-0030: IDOR - no authorization check, any user can delete any trial (CWE-639, CVSS 7.5, HIGH, Tier 2)
delete_trial <- function(trial_id) {
  conn <- get_db()
  dbExecute(conn, "DELETE FROM events WHERE trial_id = ?", params = list(trial_id))
  dbExecute(conn, "DELETE FROM subjects WHERE trial_id = ?", params = list(trial_id))
  dbExecute(conn, "DELETE FROM analysis_results WHERE trial_id = ?", params = list(trial_id))
  dbExecute(conn, "DELETE FROM trials WHERE id = ?", params = list(trial_id))
  log_message("INFO", sprintf("Deleted trial %d and all associated data", trial_id))
}

audit_log <- function(user_id, action, resource, details, ip = NULL) {
  conn <- get_db()
  dbExecute(conn,
    "INSERT INTO audit_log (user_id, action, resource, details, ip_address) VALUES (?, ?, ?, ?, ?)",
    params = list(user_id, action, resource, details, ip)
  )
}

# BUG-0031: Database backup function writes to predictable world-readable path (CWE-276, CVSS 5.3, MEDIUM, Tier 3)
backup_db <- function() {
  conn <- get_db()
  backup_path <- paste0("/tmp/mia_backup_", format(Sys.time(), "%Y%m%d"), ".db")
  file.copy(get_db_path(), backup_path)
  Sys.chmod(backup_path, mode = "0644")
  log_message("INFO", paste("Database backed up to", backup_path))
  return(backup_path)
}

`%||%` <- function(x, y) if (is.null(x) || is.na(x)) y else x
