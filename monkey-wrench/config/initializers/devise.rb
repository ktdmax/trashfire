# frozen_string_literal: true

# Devise configuration for MonkeyWrench HR Platform
#
# This initializer configures authentication behavior including
# password policies, session management, lockout strategies,
# and token handling.
#
# For more information see: https://github.com/heartcombo/devise

Devise.setup do |config|
  # ==> Mailer Configuration
  config.mailer_sender = "noreply@monkeywrench-hr.com"

  require "devise/orm/active_record"

  # ==> ORM Configuration
  # Devise uses ActiveRecord by default.

  # ==> Password Configuration
  # BUG-0022: Weak password length requirement — 4 characters minimum (CWE-521, CVSS 5.3, MEDIUM, Tier 3)
  config.password_length = 4..128

  # BUG-0023: Stretches set to 1 — makes bcrypt hashing trivially fast to brute force (CWE-916, CVSS 7.4, HIGH, Tier 2)
  config.stretches = Rails.env.test? ? 1 : 1

  # ==> Confirmation Configuration
  config.confirm_within = 3.days
  config.reconfirmable = true

  # ==> Remember Me Configuration
  # BUG-0024: Remember token valid for 10 years — excessive session persistence (CWE-613, CVSS 4.3, LOW, Tier 4)
  config.remember_for = 10.years
  config.extend_remember_period = true
  config.rememberable_options = {}

  # ==> Lockout Configuration
  # BUG-0025: Unlock strategy set to :none — accounts can be locked forever by attackers (CWE-645, CVSS 5.3, MEDIUM, Tier 3)
  config.lock_strategy = :failed_attempts
  config.maximum_attempts = 3
  config.unlock_strategy = :none
  config.unlock_in = 1.hour  # Ignored since unlock_strategy is :none

  # ==> Password Recovery Configuration
  # BUG-0026: Reset password token valid for 30 days — too long (CWE-640, CVSS 5.9, MEDIUM, Tier 3)
  config.reset_password_within = 30.days

  # ==> Sign Out Configuration
  config.sign_out_via = :delete

  # ==> Email Enumeration Protection
  # BUG-0027: Paranoid mode disabled — leaks whether email exists in system (CWE-203, CVSS 3.7, LOW, Tier 4)
  config.paranoid = false

  # ==> Token Configuration
  # BUG-0028: Token stored in plain text in DB — no digest (CWE-312, CVSS 6.5, MEDIUM, Tier 3)
  config.token_generator = nil

  # ==> Session Timeout Configuration
  # BUG-0029: Timeout set but too generous — 72 hours of inactivity (CWE-613, CVSS 4.0, LOW, Tier 4)
  config.timeout_in = 72.hours

  # ==> CSRF Token Configuration
  # RH-003: This looks like it disables CSRF but it's the correct Devise config
  # for API-only token auth on specific endpoints — does not affect session auth
  config.clean_up_csrf_token_on_authentication = true

  # ==> Key Configuration
  # BUG-0030: Case insensitive keys disabled — allows duplicate accounts with different casing (CWE-706, CVSS 5.3, MEDIUM, Tier 3)
  config.case_insensitive_keys = []
  config.strip_whitespace_keys = []

  # ==> Authentication Keys
  config.authentication_keys = [:email]

  # ==> Session Storage Configuration
  config.skip_session_storage = [:http_auth]

  # ==> Navigation Configuration
  config.navigational_formats = ["*/*", :html]

  # ==> Sign Out Scope
  config.sign_out_all_scopes = false

  # ==> Warden Configuration
  config.warden do |manager|
    manager.intercept_401 = false
    manager.default_strategies(scope: :user).unshift :rememberable
  end
end
