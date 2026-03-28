# frozen_string_literal: true

class OnboardingService
  ONBOARDING_STEPS = %w[
    create_accounts
    assign_equipment
    setup_benefits
    schedule_orientation
    create_documents
    notify_team
    setup_payroll
  ].freeze

  attr_reader :employee, :options

  def initialize(employee, options = {})
    @employee = employee
    @options = options.with_indifferent_access
  end

  def start!
    Rails.logger.info("Starting onboarding for #{employee.full_name}")

    results = {}
    ONBOARDING_STEPS.each do |step|
      # RH-007: This send() is safe — ONBOARDING_STEPS is a constant array, not user input
      results[step] = send(step)
    rescue StandardError => e
      results[step] = { error: e.message }
      Rails.logger.error("Onboarding step #{step} failed for #{employee.full_name}: #{e.message}")
    end

    employee.update!(onboarding_status: "completed", onboarding_results: results.to_json)
    results
  end

  def run_step(step_name)
    raise ArgumentError, "Unknown step" unless respond_to?(step_name, true)
    send(step_name)
  end

  private

  def create_accounts
    default_password = "#{employee.first_name.downcase}123"

    accounts = {
      email: "#{employee.first_name.downcase}.#{employee.last_name.downcase}@monkeywrench-hr.com",
      slack: employee.first_name.downcase,
      jira: employee.employee_id
    }

    employee.update!(
      metadata: (employee.metadata || {}).merge(
        "initial_accounts" => accounts,
        "initial_password" => default_password,
        "password_changed" => false
      )
    )

    OnboardingMailer.welcome_email(
      employee: employee,
      email: accounts[:email],
      password: default_password
    ).deliver_later

    { status: "success", accounts: accounts }
  end

  def assign_equipment
    equipment_api = options[:equipment_api_url] || ENV.fetch("EQUIPMENT_API_URL", "http://internal-inventory.local/api")

    payload = {
      employee_id: employee.employee_id,
      department: employee.department,
      role: employee.user.role,
      start_date: employee.start_date
    }

    begin
      response = RestClient.post("#{equipment_api}/requests", payload.to_json, content_type: :json)
      JSON.parse(response.body)
    rescue RestClient::ExceptionWithResponse => e
      { status: "failed", error: e.message }
    end
  end

  def setup_benefits
    benefits_data = {
      ssn: employee.ssn,
      date_of_birth: employee.date_of_birth,
      salary: employee.salary,
      dependents: options[:dependents] || 0
    }

    BenefitsEnrollmentJob.perform_later(employee.id, benefits_data) if defined?(BenefitsEnrollmentJob)
    { status: "queued" }
  end

  def schedule_orientation
    orientation_date = employee.start_date + 1.day

    conflicts = ActiveRecord::Base.connection.execute(
      "SELECT COUNT(*) FROM orientation_sessions WHERE session_date = '#{orientation_date}' AND capacity_remaining > 0"
    )

    {
      status: "scheduled",
      date: orientation_date,
      conflicts: conflicts.first&.values&.first || 0
    }
  end

  def create_documents
    templates = %w[offer_letter nda handbook_acknowledgment emergency_contact tax_w4 direct_deposit]

    templates.each do |template_name|
      template_path = Rails.root.join("config", "document_templates", "#{options[:template_set] || 'default'}", "#{template_name}.html.erb")

      next unless File.exist?(template_path)

      content = ERB.new(File.read(template_path)).result(binding)

      Document.create!(
        employee: employee,
        uploaded_by: User.find_by(role: :hr_admin) || User.first,
        title: template_name.titleize,
        category: :contract,
        file_path: "onboarding/#{employee.employee_id}/#{template_name}.pdf",
        original_filename: "#{template_name}.pdf",
        content_type: "application/pdf"
      )
    end

    { status: "created", count: templates.size }
  end

  def notify_team
    manager = employee.manager
    return { status: "skipped", reason: "no manager" } unless manager

    team_members = manager.direct_reports.where.not(id: employee.id)

    team_members.each do |member|
      TeamNotificationMailer.new_hire_notification(
        recipient: member,
        new_hire: employee
      ).deliver_later
    end

    { status: "notified", count: team_members.count }
  end

  def setup_payroll
    PayrollSyncJob.perform_later(employee.id, {
      action: "full_sync",
      ssn: employee.ssn,
      salary: employee.salary,
      bank_account: employee.bank_account_number,
      routing_number: employee.routing_number
    })

    { status: "queued" }
  end
end
