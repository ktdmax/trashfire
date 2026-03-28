# Melee Island Analytics - Main Application Entry Point
# Clinical Trial Analytics Dashboard
# R/Shiny application with Plumber REST API

library(shiny)

# Source UI and Server
source("ui.R")
source("server.R")

# BUG-0007 related: Global config loaded at app startup pollutes namespace
source("R/config.R")
load_config()

# BUG-0020 related: Database connection opened at module load, never closed
source("R/database.R")
init_db()

# Application options
options(
  shiny.maxRequestSize = MAX_UPLOAD_SIZE_MB * 1024^2,
  # BUG-0010 related: Debug/verbose options enabled
  shiny.fullstacktrace = TRUE,
  shiny.sanitize.errors = FALSE,   # BUG-0071 related: Full error messages sent to client
  shiny.trace = DEBUG_MODE
)

# Launch the application
shinyApp(ui = ui, server = server)
