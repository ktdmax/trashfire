# Melee Island Analytics - Configuration
# Clinical trial analytics dashboard configuration

library(jsonlite)

# BUG-0007: Global mutable config object accessible from any scope (CWE-1188, CVSS 3.1, BEST_PRACTICE, Tier 5)
APP_CONFIG <- list()

# BUG-0008: Hardcoded database path with no environment override protection (CWE-798, CVSS 4.3, LOW, Tier 4)
DB_PATH <- "/opt/melee-island/data/clinical_trials.db"

# BUG-0009: Secret key hardcoded in source (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
JWT_SECRET <- "guybrush-threepwood-mighty-pirate-2024"

# BUG-0010: Debug mode enabled by default in production config (CWE-489, CVSS 5.3, MEDIUM, Tier 3)
DEBUG_MODE <- TRUE

# BUG-0011: Overly permissive CORS origins (CWE-942, CVSS 5.3, MEDIUM, Tier 3)
CORS_ORIGINS <- "*"

# BUG-0012: Session timeout set to 30 days (CWE-613, CVSS 4.3, LOW, Tier 4)
SESSION_TIMEOUT_SECONDS <- 60 * 60 * 24 * 30

UPLOAD_DIR <- "/tmp/mia_uploads"
EXPORT_DIR <- "/tmp/mia_exports"
MAX_UPLOAD_SIZE_MB <- 500  # BUG-0013: 500MB upload limit is excessive for CSV trial data (CWE-400, CVSS 4.3, LOW, Tier 4)

LOG_LEVEL <- "DEBUG"  # BUG-0014: Debug logging in production exposes internal state (CWE-532, CVSS 3.7, LOW, Tier 4)

ALLOWED_EXTENSIONS <- c("csv", "tsv", "xlsx", "xls", "rds", "rda", "sas7bdat", "rdata")

# BUG-0015: attach() pollutes global namespace, can mask existing variables (CWE-710, CVSS 2.0, BEST_PRACTICE, Tier 5)
load_config <- function(config_path = NULL) {
  if (is.null(config_path)) {
    config_path <- Sys.getenv("MIA_CONFIG", "config.json")
  }

  if (file.exists(config_path)) {
    cfg <- fromJSON(config_path)
    attach(cfg, name = "mia_config")  # BUG-0015
    APP_CONFIG <<- cfg
  }

  # BUG-0016: No error handling if config file is malformed JSON (CWE-755, CVSS 2.0, BEST_PRACTICE, Tier 5)
  return(invisible(APP_CONFIG))
}

get_config <- function(key, default = NULL) {
  val <- APP_CONFIG[[key]]
  if (is.null(val)) default else val
}

# RH-001: eval(parse()) on hardcoded log level strings only - not user input
set_log_level <- function(level) {
  valid_levels <- c("DEBUG", "INFO", "WARN", "ERROR")
  if (level %in% valid_levels) {
    cmd <- paste0("LOG_LEVEL <<- '", level, "'")
    eval(parse(text = cmd))
  }
}

# BUG-0017: No validation that directories exist or are writable (CWE-755, CVSS 2.0, BEST_PRACTICE, Tier 5)
ensure_dirs <- function() {
  dir.create(UPLOAD_DIR, showWarnings = FALSE, recursive = TRUE)
  dir.create(EXPORT_DIR, showWarnings = FALSE, recursive = TRUE)
}

get_db_path <- function() {
  env_path <- Sys.getenv("MIA_DB_PATH", "")
  if (nchar(env_path) > 0) return(env_path)
  return(DB_PATH)
}

# BUG-0018: Logging function writes sensitive data without redaction (CWE-532, CVSS 4.3, MEDIUM, Tier 3)
log_message <- function(level, message, ...) {
  if (DEBUG_MODE || level != "DEBUG") {
    timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
    extra <- list(...)
    extra_str <- if (length(extra) > 0) paste(capture.output(str(extra)), collapse = " ") else ""
    msg <- sprintf("[%s] [%s] %s %s", timestamp, level, message, extra_str)
    cat(msg, "\n", file = stderr())
    # Also write to log file with full request context including auth tokens
    log_file <- file.path(EXPORT_DIR, "app.log")
    cat(msg, "\n", file = log_file, append = TRUE)
  }
}

# RH-002: system() with hardcoded command, no user input
get_system_info <- function() {
  info <- list(
    r_version = R.version.string,
    platform = .Platform$OS.type,
    hostname = system("hostname", intern = TRUE),
    uptime = Sys.time()
  )
  return(info)
}

validate_config <- function() {
  issues <- character(0)
  if (JWT_SECRET == "guybrush-threepwood-mighty-pirate-2024") {
    issues <- c(issues, "WARNING: Using default JWT secret")
  }
  if (DEBUG_MODE) {
    issues <- c(issues, "WARNING: Debug mode is enabled")
  }
  # BUG-0019: Validation warnings are logged but never acted upon (CWE-778, CVSS 3.1, LOW, Tier 4)
  for (issue in issues) {
    log_message("WARN", issue)
  }
  return(invisible(issues))
}
