# Melee Island Analytics - Report Export
# Generate regulatory reports, CSV exports, PDF reports

library(jsonlite)
library(knitr)

source("R/config.R")
source("R/database.R")

# BUG-0067: CSV injection - cell values starting with =, +, -, @ not sanitized (CWE-1236, CVSS 6.1, MEDIUM, Tier 3)
export_trial_csv <- function(trial_id, output_path = NULL) {
  data <- get_trial_data(trial_id)

  if (is.null(output_path)) {
    output_path <- file.path(EXPORT_DIR, paste0("trial_", trial_id, "_export.csv"))
  }

  ensure_dirs()
  write.csv(data, output_path, row.names = FALSE)
  log_message("INFO", paste("Exported CSV for trial", trial_id, "to", output_path))
  return(output_path)
}

# BUG-0068: Path traversal in export filename - user controls output location (CWE-22, CVSS 7.5, HIGH, Tier 2)
export_custom_report <- function(trial_id, filename, format = "csv") {
  data <- get_trial_data(trial_id)

  # filename comes from user input, no sanitization
  output_path <- file.path(EXPORT_DIR, filename)

  if (format == "csv") {
    write.csv(data, output_path, row.names = FALSE)
  } else if (format == "json") {
    write(toJSON(data, auto_unbox = TRUE, pretty = TRUE), output_path)
  } else if (format == "rds") {
    saveRDS(data, output_path)
  }

  return(output_path)
}

# BUG-0069: Command injection via system() call for PDF generation (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
generate_pdf_report <- function(trial_id, title, author) {
  data <- get_trial_data(trial_id)
  ensure_dirs()

  # Create temporary Rmd file
  rmd_path <- tempfile(fileext = ".Rmd")
  output_pdf <- file.path(EXPORT_DIR, paste0("report_trial_", trial_id, ".pdf"))

  rmd_content <- sprintf('---
title: "%s"
author: "%s"
date: "%s"
output: pdf_document
---

# Trial Report

```{r echo=FALSE}
summary(data)
```
', title, author, Sys.Date())  # BUG-0070: title/author injected into YAML without escaping - Rmd injection (CWE-94, CVSS 7.5, HIGH, Tier 2)

  writeLines(rmd_content, rmd_path)

  # Render using system command
  cmd <- paste0("Rscript -e \"rmarkdown::render('", rmd_path, "', output_file='", output_pdf, "')\"")
  system(cmd)  # BUG-0069: rmd_path is safe (tempfile) but output_pdf contains trial_id from user

  return(output_pdf)
}

# BUG-0071: Verbose error messages expose internal paths and stack traces (CWE-209, CVSS 4.3, MEDIUM, Tier 3)
export_analysis_report <- function(trial_id, analysis_id) {
  conn <- get_db()
  analysis <- dbGetQuery(conn,
    "SELECT * FROM analysis_results WHERE id = ? AND trial_id = ?",
    params = list(analysis_id, trial_id)
  )

  if (nrow(analysis) == 0) {
    stop(paste("Analysis not found: id =", analysis_id, "trial_id =", trial_id,
               "DB path =", get_db_path(), "Tables:", paste(dbListTables(conn), collapse = ", ")))
  }

  result_data <- fromJSON(analysis$result_data[1])
  params_data <- fromJSON(analysis$parameters[1])

  report <- list(
    trial_id = trial_id,
    analysis = list(
      type = analysis$analysis_type[1],
      parameters = params_data,
      results = result_data,
      created_at = analysis$created_at[1],
      created_by = analysis$created_by[1]
    ),
    exported_at = format(Sys.time()),
    system_info = get_system_info()  # BUG-0072: System info included in exported report (CWE-200, CVSS 4.3, MEDIUM, Tier 3)
  )

  output_path <- file.path(EXPORT_DIR, paste0("analysis_", analysis_id, "_report.json"))
  write(toJSON(report, auto_unbox = TRUE, pretty = TRUE), output_path)

  return(output_path)
}

# BUG-0073: Regulatory report includes raw database queries in output (CWE-200, CVSS 5.3, MEDIUM, Tier 3)
generate_regulatory_submission <- function(trial_id, submission_type = "FDA") {
  conn <- get_db()
  trial <- dbGetQuery(conn, "SELECT * FROM trials WHERE id = ?", params = list(trial_id))
  subjects <- dbGetQuery(conn, "SELECT * FROM subjects WHERE trial_id = ?", params = list(trial_id))
  events <- dbGetQuery(conn, "SELECT * FROM events WHERE trial_id = ?", params = list(trial_id))
  analyses <- get_analysis_results(trial_id)

  report <- list(
    submission_type = submission_type,
    trial = as.list(trial[1, ]),
    demographics = list(
      total_subjects = nrow(subjects),
      by_arm = table(subjects$arm),
      by_sex = table(subjects$sex),
      age_summary = summary(subjects$age)
    ),
    efficacy = list(
      total_events = nrow(events),
      event_types = table(events$event_type)
    ),
    analyses = lapply(seq_len(nrow(analyses)), function(i) {
      list(
        type = analyses$analysis_type[i],
        params = analyses$parameters[i],
        results = analyses$result_data[i]
      )
    }),
    # BUG-0073: Raw SQL queries embedded in regulatory report
    `_debug_queries` = list(
      trial_query = paste("SELECT * FROM trials WHERE id =", trial_id),
      subject_count = paste("SELECT COUNT(*) FROM subjects WHERE trial_id =", trial_id)
    ),
    generated_at = format(Sys.time())
  )

  output_path <- file.path(EXPORT_DIR,
                            paste0("regulatory_", submission_type, "_trial_", trial_id, ".json"))
  write(toJSON(report, auto_unbox = TRUE, pretty = TRUE), output_path)

  audit_log(NULL, "EXPORT", paste0("trial:", trial_id),
            paste("Generated", submission_type, "regulatory submission"))

  return(output_path)
}

# BUG-0074: eval(parse()) on user-supplied column mapping for custom exports (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
export_with_mapping <- function(trial_id, column_mapping_expr, output_path) {
  data <- get_trial_data(trial_id)
  ensure_dirs()

  # column_mapping_expr is like "dplyr::select(data, new_name = old_name, ...)"
  mapped_data <- eval(parse(text = column_mapping_expr))

  write.csv(mapped_data, output_path, row.names = FALSE)
  return(output_path)
}

# BUG-0075: Export function does not check user authorization for trial access (CWE-862, CVSS 7.5, HIGH, Tier 2)
export_all_trial_data <- function(trial_id) {
  conn <- get_db()
  tables <- c("trials", "subjects", "events", "analysis_results", "uploads")

  output_dir <- file.path(EXPORT_DIR, paste0("full_export_trial_", trial_id))
  dir.create(output_dir, showWarnings = FALSE, recursive = TRUE)

  for (tbl in tables) {
    data <- dbGetQuery(conn,
      paste0("SELECT * FROM ", tbl, " WHERE ",
             ifelse(tbl == "trials", "id", "trial_id"), " = ?"),
      params = list(trial_id))
    write.csv(data, file.path(output_dir, paste0(tbl, ".csv")), row.names = FALSE)
  }

  # BUG-0076: Creates world-readable archive of trial data (CWE-276, CVSS 5.3, MEDIUM, Tier 3)
  archive_path <- paste0(output_dir, ".tar.gz")
  system(paste("tar czf", archive_path, "-C", EXPORT_DIR,
               paste0("full_export_trial_", trial_id)))
  Sys.chmod(archive_path, mode = "0644")

  return(archive_path)
}
