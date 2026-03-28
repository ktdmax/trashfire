# Melee Island Analytics - Docker Image
# Clinical trial analytics dashboard

FROM rocker/shiny:4.3.0

LABEL maintainer="analytics@melee-island.local"
LABEL description="Clinical Trial Analytics Dashboard"

RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    libsqlite3-dev \
    sqlite3 \
    pandoc \
    texlive-latex-base \
    texlive-fonts-recommended \
    && rm -rf /var/lib/apt/lists/*

# Install R packages
RUN R -e "install.packages(c( \
    'shiny', 'plumber', 'DBI', 'RSQLite', 'dplyr', \
    'survival', 'ggplot2', 'DT', 'jsonlite', \
    'jose', 'digest', 'openssl', 'readxl', \
    'knitr', 'rmarkdown', 'haven', 'rlang', 'tools' \
  ), repos='https://cran.r-project.org/')"

WORKDIR /app

# Copy application files
COPY . /app/

# Initialize database with schema (includes default admin credentials from schema.sql)
RUN mkdir -p /opt/melee-island/data && \
    sqlite3 /opt/melee-island/data/clinical_trials.db < /app/data/schema.sql

RUN mkdir -p /tmp/mia_uploads /tmp/mia_exports && \
    chmod 777 /tmp/mia_uploads /tmp/mia_exports

EXPOSE 3838 8000

# Start both Shiny app and Plumber API
CMD ["sh", "-c", "R -e \"plumber::pr_run(plumber::pr('api/plumber.R'), host='0.0.0.0', port=8000)\" & R -e \"shiny::runApp('/app', host='0.0.0.0', port=3838)\""]
