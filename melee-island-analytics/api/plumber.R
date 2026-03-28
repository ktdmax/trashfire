# Melee Island Analytics - Plumber REST API
# REST API for clinical trial data access and analysis

library(plumber)
library(jsonlite)

source("R/config.R")
source("R/database.R")
source("R/auth.R")
source("R/analysis.R")
source("R/upload.R")
source("R/export.R")

#* @apiTitle Melee Island Analytics API
#* @apiDescription Clinical trial analytics REST API

# BUG-0077: CORS filter allows all origins with credentials (CWE-942, CVSS 6.5, HIGH, Tier 2)
#* @filter cors
function(req, res) {
  res$setHeader("Access-Control-Allow-Origin", CORS_ORIGINS)
  res$setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
  res$setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
  res$setHeader("Access-Control-Allow-Credentials", "true")  # BUG-0077: credentials with wildcard origin
  if (req$REQUEST_METHOD == "OPTIONS") {
    res$status <- 200
    return(list())
  }
  plumber::forward()
}

# BUG-0078: Auth filter logs full authorization header including tokens (CWE-532, CVSS 5.3, MEDIUM, Tier 3)
#* @filter auth
function(req, res) {
  # Skip auth for login/register endpoints
  if (grepl("^/(login|register|health)", req$PATH_INFO)) {
    return(plumber::forward())
  }

  log_message("DEBUG", paste("Auth check for:", req$PATH_INFO,
                              "Header:", req$HTTP_AUTHORIZATION))  # BUG-0078

  # Check API key first
  api_key <- req$HTTP_X_API_KEY
  if (!is.null(api_key) && nchar(api_key) > 0) {
    user <- authenticate_api_key(api_key)
    if (!is.null(user)) {
      req$user <- user
      return(plumber::forward())
    }
  }

  # Check JWT
  auth_header <- req$HTTP_AUTHORIZATION
  if (!is.null(auth_header) && grepl("^Bearer ", auth_header)) {
    token <- sub("^Bearer ", "", auth_header)
    payload <- verify_jwt(token)
    if (!is.null(payload)) {
      req$user <- list(id = payload$sub, username = payload$usr, role = payload$role)
      return(plumber::forward())
    }
  }

  # BUG-0079: Missing auth returns 401 but still processes some endpoints due to filter ordering (CWE-862, CVSS 7.5, HIGH, Tier 2)
  res$status <- 401
  return(list(error = "Authentication required"))
}

#* Health check
#* @get /health
#* @serializer unboxedJSON
function() {
  list(status = "ok", version = "1.0.0", debug = DEBUG_MODE)
}

#* Login
#* @post /login
#* @serializer unboxedJSON
function(req, res) {
  body <- fromJSON(req$postBody)
  result <- authenticate_user(body$username, body$password)
  if (is.null(result)) {
    res$status <- 401
    return(list(error = "Invalid credentials"))
  }
  return(result)
}

#* Register new user
#* @post /register
#* @serializer unboxedJSON
function(req, res) {
  body <- fromJSON(req$postBody)
  # BUG-0080: User registration endpoint is publicly accessible, no invite/approval required (CWE-862, CVSS 6.5, MEDIUM, Tier 3)
  result <- register_user(body$username, body$email, body$password, body$role %||% "analyst")
  if (!result$success) {
    res$status <- 400
    return(list(error = result$error))
  }
  return(list(success = TRUE, user_id = result$user_id, api_key = result$api_key))
}

#* List trials
#* @get /trials
#* @serializer unboxedJSON
function(req) {
  conn <- get_db()
  # BUG-0081: No pagination on trial listing, returns all records (CWE-400, CVSS 3.7, LOW, Tier 4)
  trials <- dbGetQuery(conn, "SELECT * FROM trials")
  return(trials)
}

#* Search trials
#* @get /trials/search
#* @param q Search query
#* @serializer unboxedJSON
function(q, req) {
  return(search_trials(q, req$user$id))  # BUG-0025 called here with user input
}

#* Get trial details
#* @get /trials/<trial_id:int>
#* @serializer unboxedJSON
function(trial_id, req) {
  conn <- get_db()
  # BUG-0082: IDOR - no check that user has access to this trial (CWE-639, CVSS 7.5, HIGH, Tier 2)
  trial <- dbGetQuery(conn, "SELECT * FROM trials WHERE id = ?", params = list(trial_id))
  if (nrow(trial) == 0) {
    return(list(error = "Trial not found"))
  }
  return(as.list(trial[1, ]))
}

#* Get trial data with filters
#* @get /trials/<trial_id:int>/data
#* @param arm Filter by arm
#* @param status Filter by status
#* @param site_id Filter by site
#* @serializer unboxedJSON
function(trial_id, arm = NULL, status = NULL, site_id = NULL) {
  filters <- list(arm = arm, status = status, site_id = site_id)
  data <- get_trial_data(trial_id, filters)  # BUG-0022/0023 propagated
  return(data)
}

#* Delete trial
#* @delete /trials/<trial_id:int>
#* @serializer unboxedJSON
function(trial_id, req, res) {
  # BUG-0083: No admin role check on delete operation (CWE-862, CVSS 8.1, HIGH, Tier 2)
  delete_trial(trial_id)
  return(list(success = TRUE, message = paste("Trial", trial_id, "deleted")))
}

#* Run analysis
#* @post /trials/<trial_id:int>/analyze
#* @serializer unboxedJSON
function(trial_id, req, res) {
  body <- fromJSON(req$postBody)

  if (body$method == "custom") {
    # BUG-0084: Exposes run_custom_analysis which allows command injection (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    result <- run_custom_analysis(trial_id, body$script, body$params)
  } else {
    result <- run_survival_analysis(trial_id, body$formula, body$method, body$params)
  }

  if (result$success %||% FALSE) {
    save_analysis_result(trial_id, body$method %||% "km",
                         toJSON(body$params, auto_unbox = TRUE),
                         toJSON(result, auto_unbox = TRUE),
                         req$user$id)
  }

  return(result)
}

#* Upload trial data file
#* @post /trials/<trial_id:int>/upload
#* @serializer unboxedJSON
function(trial_id, req, res) {
  # BUG-0085: No file size check at API level before processing (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
  file_data <- req$body$file
  if (is.null(file_data)) {
    res$status <- 400
    return(list(error = "No file provided"))
  }

  validation <- validate_upload(file_data$name, file_data$size)
  if (!validation$valid) {
    res$status <- 400
    return(list(error = validation$error))
  }

  upload_result <- save_upload(file_data$tmp_name, file_data$name, trial_id, req$user$id)
  process_result <- process_upload(upload_result$id)

  return(list(upload_id = upload_result$id, processed = process_result$success,
              rows = process_result$rows, cols = process_result$cols))
}

#* Download uploaded file
#* @get /uploads/<upload_id:int>/download
#* @serializer contentType list(type="application/octet-stream")
function(upload_id, req, res) {
  file_path <- get_upload_file(upload_id)  # BUG-0054 propagated
  if (is.null(file_path) || !file.exists(file_path)) {
    res$status <- 404
    return(list(error = "File not found"))
  }
  readBin(file_path, "raw", n = file.info(file_path)$size)
}

#* Export trial data
#* @get /trials/<trial_id:int>/export
#* @param format Export format (csv, json, rds)
#* @param filename Custom filename
#* @serializer unboxedJSON
function(trial_id, format = "csv", filename = NULL, req) {
  if (!is.null(filename)) {
    path <- export_custom_report(trial_id, filename, format)  # BUG-0068 propagated
  } else {
    path <- export_trial_csv(trial_id)
  }
  return(list(success = TRUE, path = path))
}

#* Generate regulatory report
#* @post /trials/<trial_id:int>/regulatory
#* @serializer unboxedJSON
function(trial_id, req) {
  body <- fromJSON(req$postBody)
  path <- generate_regulatory_submission(trial_id, body$type %||% "FDA")
  return(list(success = TRUE, path = path))
}

# BUG-0086: SSRF - fetches arbitrary URL provided by user (CWE-918, CVSS 8.6, HIGH, Tier 2)
#* Import data from external URL
#* @post /import/url
#* @serializer unboxedJSON
function(req, res) {
  body <- fromJSON(req$postBody)
  url <- body$url

  # Download file from user-provided URL
  tmp_file <- tempfile()
  download.file(url, tmp_file, mode = "wb", quiet = TRUE)  # BUG-0086: No URL validation

  data <- tryCatch({
    if (grepl("\\.csv$", url)) {
      read.csv(tmp_file, stringsAsFactors = FALSE)
    } else if (grepl("\\.rds$", url)) {
      readRDS(tmp_file)  # BUG-0087: readRDS on URL-fetched file - RCE via deserialization (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    } else {
      read.delim(tmp_file, stringsAsFactors = FALSE)
    }
  }, error = function(e) {
    res$status <- 400
    return(list(error = e$message))
  })

  unlink(tmp_file)
  return(list(success = TRUE, rows = nrow(data), cols = ncol(data), preview = head(data, 5)))
}

# BUG-0088: Admin endpoint to run arbitrary R expressions - no role check in filter for this path (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
#* Execute R expression (admin only)
#* @post /admin/eval
#* @serializer unboxedJSON
function(req, res) {
  body <- fromJSON(req$postBody)

  if (is.null(req$user) || req$user$role != "admin") {
    res$status <- 403
    return(list(error = "Admin access required"))
  }

  # Even with role check, eval on user input is RCE
  result <- eval(parse(text = body$expression))
  return(list(result = capture.output(print(result))))
}

# RH-005: eval(parse()) on validated/sanitized input - computes safe aggregate expressions
#* Compute aggregate stat
#* @get /trials/<trial_id:int>/aggregate
#* @param stat Statistic to compute (mean, median, sum, count)
#* @serializer unboxedJSON
function(trial_id, stat = "mean") {
  valid_stats <- c("mean", "median", "sum", "count")
  if (!(stat %in% valid_stats)) {
    return(list(error = "Invalid statistic. Use: mean, median, sum, count"))
  }
  data <- get_trial_data(trial_id)
  if (stat == "count") {
    result <- nrow(data)
  } else {
    expr <- paste0(stat, "(data$time_to_event, na.rm = TRUE)")
    result <- eval(parse(text = expr))
  }
  return(list(trial_id = trial_id, statistic = stat, value = result))
}

#* Backup database (admin)
#* @post /admin/backup
#* @serializer unboxedJSON
function(req, res) {
  # BUG-0089: No admin role check on backup endpoint (CWE-862, CVSS 6.5, MEDIUM, Tier 3)
  path <- backup_db()
  return(list(success = TRUE, path = path))
}
