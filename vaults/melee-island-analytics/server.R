# Melee Island Analytics - Shiny Server Logic
# Server-side logic for clinical trial analytics dashboard

library(shiny)
library(DT)
library(survival)
library(jsonlite)
library(ggplot2)

source("R/config.R")
source("R/database.R")
source("R/auth.R")
source("R/analysis.R")
source("R/upload.R")
source("R/export.R")

server <- function(input, output, session) {

  # BUG-0099: Session state stored in reactiveValues without per-user isolation (CWE-200, CVSS 5.3, TRICKY, Tier 6)
  user_state <- reactiveValues(
    authenticated = FALSE,
    user = NULL,
    token = NULL,
    session_token = NULL,
    current_trial = NULL,
    trial_data = NULL,
    analysis_result = NULL
  )

  # Initialize database on app start
  observe({
    init_db()
    ensure_dirs()
    validate_config()
  })

  # --- Authentication ---

  observeEvent(input$login_btn, {
    result <- authenticate_user(input$login_username, input$login_password)
    if (!is.null(result)) {
      user_state$authenticated <- TRUE
      user_state$user <- result$user
      user_state$token <- result$token
      user_state$session_token <- result$session
      updateNavbarPage(session, "main_nav", selected = "Dashboard")

      # Load trials
      conn <- get_db()
      trials <- dbGetQuery(conn, "SELECT id, trial_code, title FROM trials")
      choices <- setNames(trials$id, paste(trials$trial_code, "-", trials$title))
      updateSelectInput(session, "trial_select", choices = choices)
      updateSelectInput(session, "upload_trial", choices = choices)
      updateSelectInput(session, "export_trial", choices = choices)
    } else {
      # BUG-0100: Error message reveals whether username exists (CWE-203, CVSS 3.7, LOW, Tier 4)
      conn <- get_db()
      user_exists <- dbGetQuery(conn, "SELECT COUNT(*) as cnt FROM users WHERE username = ?",
                                 params = list(input$login_username))
      if (user_exists$cnt[1] > 0) {
        output$login_message <- renderUI(tags$div(class = "text-danger", "Incorrect password"))
      } else {
        output$login_message <- renderUI(tags$div(class = "text-danger", "Username not found"))
      }
    }
  })

  observeEvent(input$register_btn, {
    result <- register_user(input$reg_username, input$reg_email,
                            input$reg_password, input$reg_role)
    if (result$success) {
      output$login_message <- renderUI(
        tags$div(class = "text-success",
                 paste("Registered successfully. API Key:", result$api_key))
        # BUG-0001 related: API key displayed in UI after registration
      )
    } else {
      output$login_message <- renderUI(tags$div(class = "text-danger", result$error))
    }
  })

  # --- Data Loading ---

  trial_data <- reactive({
    req(user_state$authenticated)
    req(input$trial_select)

    filters <- list()
    if (nchar(input$filter_arm) > 0) filters$arm <- input$filter_arm
    if (nchar(input$filter_status) > 0) filters$status <- input$filter_status
    if (nchar(input$filter_site) > 0) filters$site_id <- input$filter_site

    get_trial_data(as.integer(input$trial_select), filters)
  })

  observeEvent(input$trial_select, {
    data <- trial_data()
    if (nrow(data) > 0 && "arm" %in% names(data)) {
      arms <- unique(data$arm)
      updateSelectInput(session, "filter_arm", choices = c("All" = "", arms))
    }
  })

  # --- Dashboard Outputs ---

  output$total_subjects <- renderText({
    data <- trial_data()
    paste("Total Subjects:", nrow(data))
  })

  output$total_events <- renderText({
    data <- trial_data()
    events <- sum(data$censored == 0, na.rm = TRUE)
    paste("Events:", events)
  })

  output$median_followup <- renderText({
    data <- trial_data()
    median_fu <- round(median(data$time_to_event, na.rm = TRUE), 1)
    paste("Median Follow-up:", median_fu)
  })

  output$enrollment_rate <- renderText({
    data <- trial_data()
    n_sites <- length(unique(data$site_id))
    rate <- round(nrow(data) / max(n_sites, 1), 1)
    paste("Subjects/Site:", rate)
  })

  output$trial_data_table <- DT::renderDT({
    datatable(trial_data(), options = list(pageLength = 25, scrollX = TRUE))
  })

  output$enrollment_plot <- renderPlot({
    data <- trial_data()
    if (nrow(data) > 0 && "enrollment_date" %in% names(data)) {
      data$enrollment_date <- as.Date(data$enrollment_date)
      ggplot(data, aes(x = enrollment_date, fill = arm)) +
        geom_histogram(bins = 30) +
        labs(title = "Enrollment Over Time", x = "Date", y = "Count") +
        theme_minimal()
    }
  })

  output$event_timeline <- renderPlot({
    data <- trial_data()
    if (nrow(data) > 0) {
      ggplot(data, aes(x = time_to_event, fill = factor(censored))) +
        geom_histogram(bins = 30, position = "stack") +
        labs(title = "Time to Event Distribution", x = "Time", y = "Count",
             fill = "Censored") +
        theme_minimal()
    }
  })

  output$age_dist_plot <- renderPlot({
    data <- trial_data()
    if (nrow(data) > 0 && "age" %in% names(data)) {
      ggplot(data, aes(x = age, fill = arm)) +
        geom_density(alpha = 0.5) +
        labs(title = "Age Distribution by Arm") +
        theme_minimal()
    }
  })

  output$sex_dist_plot <- renderPlot({
    data <- trial_data()
    if (nrow(data) > 0 && "sex" %in% names(data)) {
      ggplot(data, aes(x = sex, fill = arm)) +
        geom_bar(position = "dodge") +
        labs(title = "Sex Distribution by Arm") +
        theme_minimal()
    }
  })

  output$demographics_table <- renderTable({
    data <- trial_data()
    if (nrow(data) > 0) {
      data %>%
        group_by(arm) %>%
        summarise(
          N = n(),
          `Mean Age` = round(mean(age, na.rm = TRUE), 1),
          `Male %` = round(100 * mean(sex == "M", na.rm = TRUE), 1),
          `Median FU` = round(median(time_to_event, na.rm = TRUE), 1)
        )
    }
  })

  # --- Analysis ---

  observeEvent(input$run_analysis, {
    req(user_state$authenticated)
    trial_id <- as.integer(input$trial_select)

    # BUG-0093 propagated: formula from text input -> eval(parse())
    result <- run_survival_analysis(
      trial_id,
      input$analysis_formula,
      input$analysis_method
    )

    user_state$analysis_result <- result

    if (isTRUE(result$success)) {
      save_analysis_result(
        trial_id, input$analysis_method,
        toJSON(list(formula = input$analysis_formula), auto_unbox = TRUE),
        toJSON(result, auto_unbox = TRUE),
        user_state$user$id
      )
    }
  })

  observeEvent(input$run_subgroup, {
    req(user_state$authenticated)
    trial_id <- as.integer(input$trial_select)
    covariates <- if (nchar(input$analysis_covariates) > 0) {
      trimws(strsplit(input$analysis_covariates, ",")[[1]])
    } else {
      c()
    }
    result <- run_subgroup_analysis(trial_id, input$outcome_var, input$subgroup_var, covariates)
    user_state$analysis_result <- result
  })

  observeEvent(input$run_custom, {
    req(user_state$authenticated)
    trial_id <- as.integer(input$trial_select)

    params_text <- input$custom_params
    params <- list()
    if (nchar(params_text) > 0) {
      lines <- strsplit(params_text, "\n")[[1]]
      for (line in lines) {
        parts <- strsplit(trimws(line), "=")[[1]]
        if (length(parts) == 2) {
          params[[trimws(parts[1])]] <- trimws(parts[2])
        }
      }
    }

    # BUG-0094 propagated: custom script path from UI input -> system() call
    result <- run_custom_analysis(trial_id, input$custom_script, params)
    user_state$analysis_result <- list(success = TRUE, output = result)
  })

  output$analysis_output <- renderPrint({
    req(user_state$analysis_result)
    result <- user_state$analysis_result
    if (isTRUE(result$success)) {
      cat("Analysis completed successfully\n\n")
      if (!is.null(result$output)) {
        cat(paste(result$output, collapse = "\n"))
      } else {
        str(result)
      }
    } else {
      # BUG-0071 related: verbose error output in UI
      cat("Error:", result$error, "\n")
    }
  })

  output$analysis_table <- renderTable({
    req(user_state$analysis_result)
    result <- user_state$analysis_result
    if (!is.null(result$survival_table)) {
      result$survival_table
    } else if (!is.null(result$coefficients)) {
      result$coefficients
    }
  })

  output$km_plot <- renderPlot({
    req(user_state$authenticated)
    req(input$trial_select)

    data <- trial_data()
    if (nrow(data) > 0) {
      # RH-006: Eval on hardcoded survfit formula, not user-controlled here
      fit <- survfit(Surv(time_to_event, censored) ~ arm, data = data,
                     conf.int = input$km_conf_level)
      plot(fit, col = 1:length(unique(data$arm)), lwd = 2,
           xlab = "Time", ylab = "Survival Probability",
           main = "Kaplan-Meier Survival Curves")
      legend("bottomleft", legend = names(fit$strata), col = 1:length(fit$strata), lwd = 2)
    }
  })

  output$forest_plot <- renderPlot({
    req(user_state$analysis_result)
    result <- user_state$analysis_result
    if (!is.null(result$coefficients)) {
      coefs <- result$coefficients
      plot(1:nrow(coefs), exp(coefs[, 1]),
           xlim = c(0, nrow(coefs) + 1),
           ylim = c(min(exp(coefs[, 1] - 1.96 * coefs[, 3])),
                    max(exp(coefs[, 1] + 1.96 * coefs[, 3]))),
           pch = 16, xlab = "", ylab = "Hazard Ratio",
           main = "Forest Plot", xaxt = "n")
      abline(h = 1, lty = 2, col = "red")
      arrows(1:nrow(coefs),
             exp(coefs[, 1] - 1.96 * coefs[, 3]),
             1:nrow(coefs),
             exp(coefs[, 1] + 1.96 * coefs[, 3]),
             angle = 90, code = 3, length = 0.05)
      axis(1, at = 1:nrow(coefs), labels = rownames(coefs), las = 2)
    }
  })

  output$download_data <- downloadHandler(
    filename = function() {
      paste0("trial_", input$trial_select, "_data.csv")
    },
    content = function(file) {
      write.csv(trial_data(), file, row.names = FALSE)
    }
  )

  # --- Upload ---

  observeEvent(input$upload_btn, {
    req(user_state$authenticated)
    req(input$data_file)

    file_info <- input$data_file

    validation <- validate_upload(file_info$name, file_info$size)
    if (!validation$valid) {
      output$upload_status <- renderUI(
        tags$div(class = "alert alert-danger", validation$error)
      )
      return()
    }

    result <- save_upload(file_info$datapath, file_info$name,
                          as.integer(input$upload_trial), user_state$user$id)
    process_result <- process_upload(result$id)

    # BUG-0096: Unsanitized filename rendered as HTML - XSS via filename
    output$upload_status <- renderUI({
      if (process_result$success) {
        tags$div(class = "alert alert-success",
          HTML(paste0("File <strong>", file_info$name, "</strong> uploaded successfully. ",
                      "Rows: ", process_result$rows, ", Columns: ", process_result$cols)))
      } else {
        tags$div(class = "alert alert-danger",
          HTML(paste0("Failed to process <strong>", file_info$name, "</strong>: ",
                      process_result$error)))
      }
    })
  })

  observeEvent(input$import_url_btn, {
    req(user_state$authenticated)
    req(nchar(input$import_url) > 0)

    # BUG-0086 propagated: SSRF via URL import
    tmp_file <- tempfile()
    tryCatch({
      download.file(input$import_url, tmp_file, mode = "wb", quiet = TRUE)
      data <- read.csv(tmp_file, stringsAsFactors = FALSE)
      output$upload_status <- renderUI(
        tags$div(class = "alert alert-success",
                 paste("Imported", nrow(data), "rows from URL"))
      )
    }, error = function(e) {
      output$upload_status <- renderUI(
        tags$div(class = "alert alert-danger", paste("Import failed:", e$message))
      )
    })
    unlink(tmp_file)
  })

  # --- Export ---

  observeEvent(input$export_data_btn, {
    req(user_state$authenticated)
    trial_id <- as.integer(input$export_trial)

    if (nchar(input$export_filename) > 0) {
      # BUG-0068 propagated: path traversal in custom filename
      path <- export_custom_report(trial_id, input$export_filename, input$export_format)
    } else {
      path <- export_trial_csv(trial_id)
    }

    output$export_history <- renderTable({
      data.frame(File = basename(path), Format = input$export_format,
                 Time = format(Sys.time()), stringsAsFactors = FALSE)
    })
  })

  observeEvent(input$generate_report_btn, {
    req(user_state$authenticated)
    trial_id <- as.integer(input$export_trial)
    # BUG-0070 propagated: title/author injection into Rmd
    path <- generate_pdf_report(trial_id, input$report_title, input$report_author)

    showNotification(paste("Report generated:", basename(path)), type = "message")
  })

  observeEvent(input$generate_regulatory_btn, {
    req(user_state$authenticated)
    trial_id <- as.integer(input$export_trial)
    path <- generate_regulatory_submission(trial_id, input$reg_submission_type)
    showNotification(paste("Regulatory report generated:", basename(path)), type = "message")
  })

  observeEvent(input$export_mapped_btn, {
    req(user_state$authenticated)
    trial_id <- as.integer(input$export_trial)
    output_path <- file.path(EXPORT_DIR, paste0("mapped_trial_", trial_id, ".csv"))
    # BUG-0097 propagated: column mapping expression -> eval(parse())
    export_with_mapping(trial_id, input$column_mapping, output_path)
    showNotification("Exported with custom mapping", type = "message")
  })

  # --- Admin ---

  output$user_table <- DT::renderDT({
    req(user_state$authenticated)
    conn <- get_db()
    users <- dbGetQuery(conn, "SELECT id, username, email, role, last_login, is_active FROM users")
    datatable(users, options = list(pageLength = 10))
  })

  output$audit_log_table <- DT::renderDT({
    req(user_state$authenticated)
    conn <- get_db()
    # BUG-0004 related: audit log table displayed with sensitive details column
    logs <- dbGetQuery(conn, "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100")
    datatable(logs, options = list(pageLength = 10, scrollX = TRUE))
  })

  # BUG-0098 propagated: Admin eval console
  observeEvent(input$admin_eval_btn, {
    req(user_state$authenticated)
    # Only checks client-side role, which can be spoofed via reactive state manipulation
    if (user_state$user$role == "admin") {
      result <- tryCatch({
        eval(parse(text = input$admin_eval))
      }, error = function(e) {
        paste("Error:", e$message)
      })
      output$admin_eval_output <- renderPrint({
        print(result)
      })
    } else {
      output$admin_eval_output <- renderPrint({
        cat("Admin access required")
      })
    }
  })

  output$system_info <- renderPrint({
    info <- get_system_info()
    cat("R Version:", info$r_version, "\n")
    cat("Platform:", info$platform, "\n")
    cat("Hostname:", info$hostname, "\n")
    cat("Debug Mode:", DEBUG_MODE, "\n")
    cat("DB Path:", get_db_path(), "\n")  # BUG-0072 related: exposes internal paths
    cat("Upload Dir:", UPLOAD_DIR, "\n")
    cat("Export Dir:", EXPORT_DIR, "\n")
  })

  observeEvent(input$backup_db_btn, {
    req(user_state$authenticated)
    path <- backup_db()
    showNotification(paste("Backup created:", path), type = "message")
  })

  # RH-007: Reactive that looks like it might leak but is properly scoped per session
  session_analytics <- reactive({
    req(user_state$authenticated)
    list(
      login_time = Sys.time(),
      user = user_state$user$username,
      actions = isolate(input$main_nav)
    )
  })

  # Cleanup on session end
  session$onSessionEnded(function() {
    if (!is.null(user_state$session_token)) {
      tryCatch(
        logout_user(user_state$session_token),
        error = function(e) log_message("WARN", paste("Session cleanup error:", e$message))
      )
    }
  })
}
