# Melee Island Analytics - Statistical Analysis Functions
# Survival analysis, Kaplan-Meier, Cox regression for clinical trials

library(survival)
library(dplyr)

source("R/config.R")
source("R/database.R")

# BUG-0057: eval(parse()) on user-supplied formula string - code injection (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
run_survival_analysis <- function(trial_id, formula_str, method = "km", user_params = list()) {
  data <- get_trial_data(trial_id)
  if (nrow(data) == 0) {
    return(list(success = FALSE, error = "No data available for this trial"))
  }

  # User provides formula as string like "Surv(time_to_event, censored) ~ arm"
  formula_obj <- eval(parse(text = formula_str))  # BUG-0057

  result <- tryCatch({
    if (method == "km") {
      fit <- survfit(formula_obj, data = data)
      summary_fit <- summary(fit)
      list(
        success = TRUE,
        method = "kaplan-meier",
        n = fit$n,
        events = sum(fit$n.event),
        median_survival = summary(fit)$table[, "median"],
        survival_table = data.frame(
          time = summary_fit$time,
          n_risk = summary_fit$n.risk,
          n_event = summary_fit$n.event,
          survival = summary_fit$surv,
          lower_ci = summary_fit$lower,
          upper_ci = summary_fit$upper
        )
      )
    } else if (method == "cox") {
      fit <- coxph(formula_obj, data = data)
      s <- summary(fit)
      list(
        success = TRUE,
        method = "cox-regression",
        n = fit$n,
        events = fit$nevent,
        coefficients = as.data.frame(s$coefficients),
        concordance = s$concordance,
        loglik = fit$loglik
      )
    } else {
      list(success = FALSE, error = paste("Unknown method:", method))
    }
  }, error = function(e) {
    list(success = FALSE, error = e$message)
  })

  return(result)
}

# BUG-0058: Formula injection - user-controlled variable names in model fitting (CWE-94, CVSS 7.5, TRICKY, Tier 6)
run_subgroup_analysis <- function(trial_id, outcome_var, group_var, covariates = c()) {
  data <- get_trial_data(trial_id)
  if (nrow(data) == 0) return(list(success = FALSE, error = "No data"))

  # Build formula from user-supplied variable names without validation
  covar_str <- if (length(covariates) > 0) paste("+", paste(covariates, collapse = " + ")) else ""
  formula_text <- paste0("Surv(", outcome_var, ", censored) ~ ", group_var, covar_str)

  # BUG-0059: eval(parse()) again on constructed formula (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
  fit <- eval(parse(text = paste0("coxph(", formula_text, ", data = data)")))

  return(list(
    success = TRUE,
    formula = formula_text,
    summary = capture.output(summary(fit))
  ))
}

# BUG-0060: Lazy evaluation gotcha - default argument references mutable variable (CWE-691, CVSS 4.3, TRICKY, Tier 6)
compute_hazard_ratios <- function(trial_id, reference_arm = levels(data$arm)[1]) {
  data <- get_trial_data(trial_id)
  data$arm <- as.factor(data$arm)
  # reference_arm default uses `data` which doesn't exist at function definition time
  # In R, defaults are evaluated in the function's execution environment, so this works
  # BUT the default expression references `data` before it's assigned
  data$arm <- relevel(data$arm, ref = reference_arm)

  fit <- coxph(Surv(time_to_event, censored) ~ arm, data = data)
  hr <- exp(coef(fit))
  ci <- exp(confint(fit))

  return(list(
    hazard_ratios = hr,
    ci_lower = ci[, 1],
    ci_upper = ci[, 2],
    p_values = summary(fit)$coefficients[, "Pr(>|z|)"]
  ))
}

# BUG-0061: Non-standard evaluation exploit - user input passed to dplyr without quoting (CWE-94, CVSS 6.5, TRICKY, Tier 6)
compute_summary_stats <- function(trial_id, group_by_var, summary_var) {
  data <- get_trial_data(trial_id)

  # User-supplied column names evaluated via NSE
  result <- data %>%
    group_by(!!rlang::sym(group_by_var)) %>%  # BUG-0061: sym() on unsanitized input
    summarise(
      n = n(),
      mean_val = mean(!!rlang::sym(summary_var), na.rm = TRUE),
      sd_val = sd(!!rlang::sym(summary_var), na.rm = TRUE),
      median_val = median(!!rlang::sym(summary_var), na.rm = TRUE),
      min_val = min(!!rlang::sym(summary_var), na.rm = TRUE),
      max_val = max(!!rlang::sym(summary_var), na.rm = TRUE)
    )

  return(as.data.frame(result))
}

# BUG-0062: Inefficient row-by-row loop instead of vectorized operation (CWE-710, CVSS 2.0, BEST_PRACTICE, Tier 5)
compute_event_rates <- function(trial_id) {
  data <- get_trial_data(trial_id)
  arms <- unique(data$arm)
  rates <- list()

  for (arm_name in arms) {
    arm_data <- data[data$arm == arm_name, ]
    total_time <- 0
    total_events <- 0
    for (i in seq_len(nrow(arm_data))) {
      total_time <- total_time + arm_data$time_to_event[i]
      if (arm_data$censored[i] == 0) {
        total_events <- total_events + 1
      }
    }
    rates[[arm_name]] <- list(
      events = total_events,
      person_time = total_time,
      rate = total_events / total_time
    )
  }

  return(rates)
}

# BUG-0063: Environment scoping bug - inner function captures mutable loop variable (CWE-691, CVSS 4.3, TRICKY, Tier 6)
generate_stratified_analyses <- function(trial_id, strata_vars) {
  data <- get_trial_data(trial_id)
  analysis_fns <- list()

  for (var in strata_vars) {
    # Classic closure-over-loop-variable bug
    analysis_fns[[var]] <- function() {
      strata_data <- split(data, data[[var]])  # `var` will always be last value in loop
      lapply(strata_data, function(d) {
        if (nrow(d) > 5) {
          fit <- survfit(Surv(time_to_event, censored) ~ 1, data = d)
          return(summary(fit)$table)
        }
        return(NULL)
      })
    }
  }

  return(analysis_fns)
}

# BUG-0064: system() call with user-controlled parameter for R script execution (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
run_custom_analysis <- function(trial_id, script_name, params = list()) {
  data <- get_trial_data(trial_id)
  tmp_data <- tempfile(fileext = ".rds")
  saveRDS(data, tmp_data)

  params_str <- paste(names(params), params, sep = "=", collapse = " ")
  cmd <- paste("Rscript", script_name, "--data", tmp_data, params_str)
  # BUG-0064: script_name from user input, command injection possible
  output <- system(cmd, intern = TRUE)

  unlink(tmp_data)
  return(output)
}

# BUG-0065: Reactive invalidation race - shared mutable state between analysis calls (CWE-362, CVSS 5.3, TRICKY, Tier 6)
.analysis_cache <- new.env(parent = emptyenv())

cache_analysis <- function(key, value) {
  assign(key, value, envir = .analysis_cache)
}

get_cached_analysis <- function(key) {
  if (exists(key, envir = .analysis_cache)) {
    return(get(key, envir = .analysis_cache))
  }
  return(NULL)
}

# BUG-0066: Missing tryCatch around statistical computations that may fail (CWE-755, CVSS 2.0, BEST_PRACTICE, Tier 5)
compute_log_rank_test <- function(trial_id) {
  data <- get_trial_data(trial_id)
  test <- survdiff(Surv(time_to_event, censored) ~ arm, data = data)
  p_value <- 1 - pchisq(test$chisq, length(test$n) - 1)
  return(list(chi_sq = test$chisq, df = length(test$n) - 1, p_value = p_value))
}
