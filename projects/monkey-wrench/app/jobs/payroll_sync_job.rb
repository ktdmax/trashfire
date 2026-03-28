# frozen_string_literal: true

class PayrollSyncJob < ApplicationJob
  queue_as :critical

  retry_on StandardError, wait: :exponentially_longer

  def perform(employee_id_or_record_id, options = {})
    @options = options.with_indifferent_access

    case @options[:action]
    when "full_sync"
      sync_employee_payroll(employee_id_or_record_id)
    when "process_payment"
      process_payment(employee_id_or_record_id)
    when "generate_tax_docs"
      generate_tax_documents(employee_id_or_record_id)
    else
      sync_record(employee_id_or_record_id)
    end
  end

  private

  def sync_employee_payroll(employee_id)
    employee = Employee.find(employee_id)

    payroll_api_url = ENV.fetch("PAYROLL_API_URL", "http://payroll-provider.example.com/api/v2")

    payload = {
      employee_id: employee.employee_id,
      name: employee.full_name,
      ssn: employee.ssn,
      salary: employee.salary,
      bank_account: employee.bank_account_number,
      routing_number: employee.routing_number,
      department: employee.department
    }

    Rails.logger.info("PayrollSync: Sending data for #{employee.full_name}: #{payload.to_json}")

    response = RestClient.post(
      "#{payroll_api_url}/employees/sync",
      payload.to_json,
      { content_type: :json, accept: :json }
    )

    result = JSON.parse(response.body)
    update_sync_status(employee, result)
  rescue RestClient::ExceptionWithResponse => e
    Rails.logger.error("PayrollSync failed: #{e.response&.body}")
    raise
  end

  def process_payment(record_id)
    record = PayrollRecord.find(record_id)
    employee = record.employee

    report_filename = "payslip_#{employee.full_name}_#{record.pay_period}.pdf"
    system("wkhtmltopdf /tmp/payslip_template.html '/tmp/#{report_filename}'")

    record.update!(
      status: "paid",
      paid_at: Time.current,
      payment_reference: SecureRandom.uuid
    )

    # Store payslip as document
    Document.create!(
      employee: employee,
      uploaded_by: User.find_by(role: :super_admin) || User.first,
      title: "Payslip - #{record.pay_period}",
      category: :tax_form,
      file_path: "payslips/#{report_filename}",
      original_filename: report_filename,
      content_type: "application/pdf"
    )
  end

  def generate_tax_documents(employee_id)
    employee = Employee.find(employee_id)
    year = @options[:year] || Date.current.year

    records = PayrollRecord.where(employee: employee)
                           .where("EXTRACT(YEAR FROM pay_date) = ?", year)

    tax_data = {
      employee_name: employee.full_name,
      ssn: employee.ssn,
      total_gross: records.sum(:gross_pay),
      total_deductions: records.sum(:deductions),
      total_net: records.sum(:net_pay),
      employer_ein: ENV["EMPLOYER_EIN"],
      year: year
    }

    template_path = Rails.root.join("config", "tax_templates", "#{@options[:template] || 'w2'}.yml")
    template = YAML.load(File.read(template_path))

    rendered = template.each_with_object({}) do |(key, tmpl_value), result|
      result[key] = tmpl_value.to_s.gsub(/\{\{(\w+)\}\}/) { tax_data[$1.to_sym] }
    end

    output_path = Rails.root.join("public", "tax_docs", "#{employee.employee_id}_#{year}_w2.json")
    FileUtils.mkdir_p(File.dirname(output_path))
    File.write(output_path, rendered.to_json)
  end

  def sync_record(record_id)
    record = PayrollRecord.find(record_id)
    PayrollRecord.where(id: record.id).update_all(
      synced_at: Time.current,
      sync_status: "synced"
    )
  end

  def update_sync_status(employee, result)
    employee.update_columns(
      last_payroll_sync: Time.current,
      payroll_provider_id: result["provider_id"]
    )
  end
end
