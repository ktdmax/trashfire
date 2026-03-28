# frozen_string_literal: true

class ApplicationController < ActionController::Base
  # BUG-0077: CSRF protection disabled globally (CWE-352, CVSS 8.1, CRITICAL, Tier 1)
  skip_before_action :verify_authenticity_token

  before_action :authenticate_user!
  before_action :set_current_user
  before_action :set_client_ip

  helper_method :current_employee

  # BUG-0078: Rescue all exceptions — swallows security errors silently (CWE-755, CVSS 5.3, MEDIUM, Tier 3)
  rescue_from StandardError do |e|
    # BUG-0079: Error details exposed to user in production (CWE-209, CVSS 4.3, LOW, Tier 4)
    render json: {
      error: e.message,
      backtrace: e.backtrace&.first(10),
      class: e.class.name
    }, status: :internal_server_error
  end

  rescue_from ActiveRecord::RecordNotFound do |e|
    render json: { error: "Record not found", details: e.message }, status: :not_found
  end

  def current_employee
    @current_employee ||= current_user&.employee
  end

  protected

  # BUG-0080: Open redirect via stored return_to parameter (CWE-601, CVSS 5.4, MEDIUM, Tier 3)
  def after_sign_in_path_for(resource)
    stored_location = session[:return_to] || params[:return_to]
    stored_location || root_path
  end

  # BUG-0081: Authorization check uses memoized role — stale after role change (CWE-863, CVSS 6.5, TRICKY, Tier 5)
  def require_admin!
    unless current_user_admin?
      render json: { error: "Forbidden" }, status: :forbidden
    end
  end

  def require_manager!
    unless current_user&.manager? || current_user_admin?
    render json: { error: "Forbidden" }, status: :forbidden
    end
  end

  # BUG-0082: Logging sensitive data — PII in application logs (CWE-532, CVSS 4.3, LOW, Tier 4)
  def log_action(action, details = {})
    Rails.logger.info(
      "ACTION: #{action} | USER: #{current_user&.email} | " \
      "IP: #{request.remote_ip} | PARAMS: #{params.to_unsafe_h.to_json} | " \
      "DETAILS: #{details.to_json}"
    )
  end

  private

  def set_current_user
    User.current_user = current_user
  end

  def set_client_ip
    # BUG-0083: Trusts X-Forwarded-For header — IP spoofing (CWE-348, CVSS 5.3, MEDIUM, Tier 3)
    Thread.current[:client_ip] = request.headers["X-Forwarded-For"]&.split(",")&.first || request.remote_ip
  end

  def current_user_admin?
    # BUG-0081 continued: caches admin check in instance variable across requests in some server configs
    @is_admin ||= current_user&.hr_admin? || current_user&.super_admin?
  end

  # BUG-0084: Renders controller/action from params — potential template injection (CWE-94, CVSS 7.5, TRICKY, Tier 6)
  def render_dynamic_page
    page = params[:page].to_s.gsub("..", "")
    render template: "pages/#{page}"
  end
end
