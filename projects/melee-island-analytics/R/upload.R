# Melee Island Analytics - File Upload Handling
# Processes CSV/TSV/RDS uploads for clinical trial data

library(tools)
library(readxl)

source("R/config.R")
source("R/database.R")

# BUG-0048: File extension check only, no MIME type or magic byte validation (CWE-434, CVSS 7.5, HIGH, Tier 2)
validate_upload <- function(filename, file_size) {
  ext <- tolower(file_ext(filename))
  if (!(ext %in% ALLOWED_EXTENSIONS)) {
    return(list(valid = FALSE, error = paste("File type not allowed:", ext)))
  }
  # BUG-0049: Size check uses MB from config but comparison is in bytes, off by factor (CWE-20, CVSS 4.3, LOW, Tier 4)
  if (file_size > MAX_UPLOAD_SIZE_MB) {
    return(list(valid = FALSE, error = "File too large"))
  }
  return(list(valid = TRUE))
}

# BUG-0050: Path traversal in filename - no sanitization of ../ sequences (CWE-22, CVSS 8.6, HIGH, Tier 2)
save_upload <- function(file_tmp_path, original_name, trial_id, user_id) {
  ensure_dirs()

  ext <- tolower(file_ext(original_name))
  # Uses original filename as part of storage path
  dest_dir <- file.path(UPLOAD_DIR, as.character(trial_id))
  dir.create(dest_dir, showWarnings = FALSE, recursive = TRUE)

  dest_path <- file.path(dest_dir, original_name)  # BUG-0050: original_name not sanitized
  file.copy(file_tmp_path, dest_path, overwrite = TRUE)

  conn <- get_db()
  dbExecute(conn,
    "INSERT INTO uploads (trial_id, filename, original_name, file_path, uploaded_by, file_size, mime_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
    params = list(trial_id, basename(dest_path), original_name, dest_path, user_id,
                  file.info(dest_path)$size, ext)
  )

  upload_id <- dbGetQuery(conn, "SELECT last_insert_rowid() as id")$id
  audit_log(user_id, "UPLOAD", paste0("trial:", trial_id), paste("Uploaded file:", original_name))

  return(list(id = upload_id, path = dest_path))
}

# BUG-0051: readRDS on user-uploaded file allows arbitrary R object deserialization / RCE (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
process_upload <- function(upload_id) {
  conn <- get_db()
  upload <- dbGetQuery(conn, "SELECT * FROM uploads WHERE id = ?", params = list(upload_id))

  if (nrow(upload) == 0) {
    return(list(success = FALSE, error = "Upload not found"))
  }

  file_path <- upload$file_path[1]
  ext <- tolower(file_ext(file_path))

  data <- tryCatch({
    if (ext == "csv") {
      read.csv(file_path, stringsAsFactors = FALSE)
    } else if (ext == "tsv") {
      read.delim(file_path, stringsAsFactors = FALSE)
    } else if (ext == "xlsx" || ext == "xls") {
      read_excel(file_path)
    } else if (ext == "rds") {
      readRDS(file_path)  # BUG-0051: Deserializes arbitrary R objects from user upload
    } else if (ext == "rda" || ext == "rdata") {
      # BUG-0052: load() executes code in RData files, even worse than readRDS (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
      env <- new.env()
      load(file_path, envir = env)
      as.list(env)
    } else if (ext == "sas7bdat") {
      haven::read_sas(file_path)
    } else {
      stop("Unsupported file format")
    }
  }, error = function(e) {
    log_message("ERROR", paste("Failed to process upload:", e$message))
    return(NULL)
  })

  if (is.null(data)) {
    return(list(success = FALSE, error = "Failed to parse file"))
  }

  # BUG-0053: No validation of column names - may contain formula injection payloads (CWE-1236, CVSS 5.3, TRICKY, Tier 6)
  dbExecute(conn, "UPDATE uploads SET processed = 1 WHERE id = ?", params = list(upload_id))

  return(list(success = TRUE, data = data, rows = nrow(data), cols = ncol(data)))
}

# RH-004: readRDS on server-generated file from known path - safe
load_cached_analysis <- function(trial_id, analysis_type) {
  cache_path <- file.path(EXPORT_DIR, "cache",
                          paste0("trial_", trial_id, "_", analysis_type, ".rds"))
  if (file.exists(cache_path)) {
    return(readRDS(cache_path))
  }
  return(NULL)
}

save_cached_analysis <- function(trial_id, analysis_type, result) {
  cache_dir <- file.path(EXPORT_DIR, "cache")
  dir.create(cache_dir, showWarnings = FALSE, recursive = TRUE)
  cache_path <- file.path(cache_dir,
                          paste0("trial_", trial_id, "_", analysis_type, ".rds"))
  saveRDS(result, cache_path)
}

# BUG-0054: File download serves any path without authorization check (CWE-22, CVSS 7.5, HIGH, Tier 2)
get_upload_file <- function(upload_id) {
  conn <- get_db()
  upload <- dbGetQuery(conn, "SELECT * FROM uploads WHERE id = ?", params = list(upload_id))
  if (nrow(upload) == 0) return(NULL)
  return(upload$file_path[1])
}

# BUG-0055: Symlink following allows reading files outside upload directory (CWE-59, CVSS 7.5, HIGH, Tier 2)
list_trial_uploads <- function(trial_id) {
  upload_dir <- file.path(UPLOAD_DIR, as.character(trial_id))
  if (!dir.exists(upload_dir)) return(character(0))
  files <- list.files(upload_dir, full.names = TRUE, recursive = TRUE)
  # Follows symlinks, could list files outside upload dir
  return(files)
}

# BUG-0056: Temporary files not cleaned up, accumulate on disk (CWE-459, CVSS 2.0, BEST_PRACTICE, Tier 5)
cleanup_temp_files <- function() {
  # Only removes files older than 24 hours but never actually called
  old_files <- list.files(UPLOAD_DIR, recursive = TRUE, full.names = TRUE)
  for (f in old_files) {
    info <- file.info(f)
    if (difftime(Sys.time(), info$mtime, units = "hours") > 24) {
      # Does not actually delete: file.remove commented out
      # file.remove(f)
      log_message("INFO", paste("Would clean up:", f))
    }
  }
}
