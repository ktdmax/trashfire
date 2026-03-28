# Melee Island Analytics - Shiny UI Components
# Clinical trial analytics dashboard UI

library(shiny)

source("R/config.R")

ui <- fluidPage(
  # BUG-0090: No Content-Security-Policy headers set (CWE-1021, CVSS 4.3, MEDIUM, Tier 3)
  tags$head(
    tags$title("Melee Island Analytics - Clinical Trial Dashboard"),
    tags$style(HTML("
      .sidebar { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }
      .analysis-panel { margin-top: 20px; }
      .status-badge { padding: 3px 8px; border-radius: 3px; font-size: 12px; }
      .status-active { background-color: #28a745; color: white; }
      .status-completed { background-color: #6c757d; color: white; }
      .upload-area { border: 2px dashed #ccc; padding: 30px; text-align: center; margin: 10px 0; }
    ")),
    # BUG-0091: Loading external JS from CDN without integrity hash (CWE-829, CVSS 5.3, MEDIUM, Tier 3)
    tags$script(src = "https://cdn.jsdelivr.net/npm/chart.js"),
    tags$script(src = "https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js")
  ),

  # Header
  div(class = "container-fluid",
    h1("Melee Island Analytics"),
    h4("Clinical Trial Analytics Dashboard", class = "text-muted"),
    hr()
  ),

  # Navigation
  navbarPage(
    title = NULL,
    id = "main_nav",

    # Login Panel
    tabPanel("Login",
      fluidRow(
        column(4, offset = 4,
          wellPanel(
            h3("Sign In"),
            textInput("login_username", "Username"),
            passwordInput("login_password", "Password"),
            actionButton("login_btn", "Login", class = "btn btn-primary btn-block"),
            hr(),
            h4("Register"),
            textInput("reg_username", "Username"),
            textInput("reg_email", "Email"),
            passwordInput("reg_password", "Password"),
            # BUG-0092: Role selection exposed in UI allows self-assignment of admin role (CWE-269, CVSS 8.8, HIGH, Tier 2)
            selectInput("reg_role", "Role", choices = c("viewer", "analyst", "admin")),
            actionButton("register_btn", "Register", class = "btn btn-default btn-block"),
            div(id = "login_message", class = "text-danger", style = "margin-top: 10px;")
          )
        )
      )
    ),

    # Dashboard
    tabPanel("Dashboard",
      fluidRow(
        column(3,
          wellPanel(class = "sidebar",
            h4("Trial Selection"),
            selectInput("trial_select", "Select Trial", choices = NULL),
            actionButton("refresh_trials", "Refresh", class = "btn btn-sm btn-default"),
            hr(),
            h4("Quick Filters"),
            selectInput("filter_arm", "Treatment Arm", choices = c("All" = ""), multiple = FALSE),
            selectInput("filter_status", "Subject Status", choices = c("All" = "", "enrolled", "completed", "withdrawn", "deceased")),
            textInput("filter_site", "Site ID"),
            actionButton("apply_filters", "Apply Filters", class = "btn btn-primary btn-sm")
          )
        ),
        column(9,
          tabsetPanel(id = "dashboard_tabs",
            tabPanel("Overview",
              fluidRow(
                textOutput("total_subjects", width = 3),
                textOutput("total_events", width = 3),
                textOutput("median_followup", width = 3),
                textOutput("enrollment_rate", width = 3)
              ),
              fluidRow(
                column(6, plotOutput("enrollment_plot", height = "300px")),
                column(6, plotOutput("event_timeline", height = "300px"))
              )
            ),
            tabPanel("Data",
              DT::DTOutput("trial_data_table"),
              downloadButton("download_data", "Download CSV")
            ),
            tabPanel("Demographics",
              fluidRow(
                column(6, plotOutput("age_dist_plot")),
                column(6, plotOutput("sex_dist_plot"))
              ),
              tableOutput("demographics_table")
            )
          )
        )
      )
    ),

    # Analysis Panel
    tabPanel("Analysis",
      fluidRow(
        column(4,
          wellPanel(
            h4("Survival Analysis"),
            selectInput("analysis_method", "Method",
                        choices = c("Kaplan-Meier" = "km", "Cox Regression" = "cox")),
            # BUG-0093: Formula input directly passed to eval(parse()) in analysis.R (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
            textInput("analysis_formula", "Formula",
                      value = "Surv(time_to_event, censored) ~ arm",
                      placeholder = "Enter survival formula"),
            textInput("analysis_covariates", "Additional Covariates (comma-separated)",
                      placeholder = "age, sex, site_id"),
            actionButton("run_analysis", "Run Analysis", class = "btn btn-success"),
            hr(),
            h4("Subgroup Analysis"),
            textInput("subgroup_var", "Grouping Variable", placeholder = "arm"),
            textInput("outcome_var", "Outcome Variable", value = "time_to_event"),
            actionButton("run_subgroup", "Run Subgroup", class = "btn btn-info"),
            hr(),
            h4("Custom Script"),
            # BUG-0094: Custom script path exposed in UI for command injection (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
            textInput("custom_script", "Script Path", placeholder = "/path/to/script.R"),
            textAreaInput("custom_params", "Parameters (key=value, one per line)", rows = 3),
            actionButton("run_custom", "Run Custom", class = "btn btn-warning")
          )
        ),
        column(8,
          tabsetPanel(
            tabPanel("Results",
              verbatimTextOutput("analysis_output"),
              tableOutput("analysis_table")
            ),
            tabPanel("Kaplan-Meier Plot",
              plotOutput("km_plot", height = "500px"),
              fluidRow(
                column(4, numericInput("km_conf_level", "Confidence Level", value = 0.95, min = 0.8, max = 0.99, step = 0.01)),
                column(4, checkboxInput("km_risk_table", "Show Risk Table", value = TRUE)),
                column(4, downloadButton("download_km_plot", "Download Plot"))
              )
            ),
            tabPanel("Forest Plot",
              plotOutput("forest_plot", height = "500px")
            )
          )
        )
      )
    ),

    # Upload Panel
    tabPanel("Upload",
      fluidRow(
        column(6,
          wellPanel(
            h4("Upload Trial Data"),
            selectInput("upload_trial", "Target Trial", choices = NULL),
            fileInput("data_file", "Choose File",
                      # BUG-0095: Accepts dangerous file types including RDS/RData (CWE-434, CVSS 7.5, HIGH, Tier 2)
                      accept = c(".csv", ".tsv", ".xlsx", ".xls", ".rds", ".rda", ".rdata", ".sas7bdat")),
            actionButton("upload_btn", "Upload & Process", class = "btn btn-primary"),
            hr(),
            h4("Import from URL"),
            textInput("import_url", "Data URL", placeholder = "https://example.com/data.csv"),
            actionButton("import_url_btn", "Import", class = "btn btn-default")
          )
        ),
        column(6,
          wellPanel(
            h4("Upload Status"),
            # BUG-0096: renderUI with unsanitized filename in HTML output (CWE-79, CVSS 6.1, HIGH, Tier 2)
            uiOutput("upload_status"),
            tableOutput("upload_history")
          )
        )
      )
    ),

    # Export Panel
    tabPanel("Export",
      fluidRow(
        column(6,
          wellPanel(
            h4("Export Data"),
            selectInput("export_trial", "Trial", choices = NULL),
            selectInput("export_format", "Format", choices = c("CSV" = "csv", "JSON" = "json", "RDS" = "rds")),
            textInput("export_filename", "Custom Filename (optional)", placeholder = "my_export.csv"),
            actionButton("export_data_btn", "Export Data", class = "btn btn-primary"),
            hr(),
            h4("Generate Report"),
            textInput("report_title", "Report Title"),
            textInput("report_author", "Author"),
            actionButton("generate_report_btn", "Generate PDF Report", class = "btn btn-info"),
            hr(),
            h4("Regulatory Submission"),
            selectInput("reg_submission_type", "Type", choices = c("FDA", "EMA", "PMDA")),
            actionButton("generate_regulatory_btn", "Generate Submission", class = "btn btn-warning")
          )
        ),
        column(6,
          wellPanel(
            h4("Export History"),
            tableOutput("export_history"),
            hr(),
            # BUG-0097: Column mapping expression input passed to eval(parse()) (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
            h4("Custom Column Mapping"),
            textAreaInput("column_mapping", "R Expression for Column Mapping",
                          value = "dplyr::select(data, subject = subject_code, treatment = arm, time = time_to_event)",
                          rows = 3),
            actionButton("export_mapped_btn", "Export with Mapping", class = "btn btn-default")
          )
        )
      )
    ),

    # Admin Panel
    tabPanel("Admin",
      fluidRow(
        column(6,
          wellPanel(
            h4("System Administration"),
            actionButton("backup_db_btn", "Backup Database", class = "btn btn-primary"),
            actionButton("view_logs_btn", "View Logs", class = "btn btn-default"),
            hr(),
            h4("User Management"),
            DT::DTOutput("user_table"),
            hr(),
            # BUG-0098: Admin eval console allows arbitrary R code execution even if session is hijacked (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
            h4("R Console (Admin)"),
            textAreaInput("admin_eval", "R Expression", rows = 5),
            actionButton("admin_eval_btn", "Execute", class = "btn btn-danger"),
            verbatimTextOutput("admin_eval_output")
          )
        ),
        column(6,
          wellPanel(
            h4("Audit Log"),
            DT::DTOutput("audit_log_table"),
            hr(),
            h4("System Info"),
            verbatimTextOutput("system_info")
          )
        )
      )
    )
  )
)
