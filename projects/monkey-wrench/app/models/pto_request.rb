# frozen_string_literal: true

class PtoRequest < ApplicationRecord
  belongs_to :employee
  belongs_to :approver, class_name: "Employee", optional: true

  enum status: { pending: 0, approved: 1, denied: 2, cancelled: 3 }
  enum pto_type: { vacation: 0, sick: 1, personal: 2, bereavement: 3, parental: 4 }

  validates :start_date, :end_date, :pto_type, presence: true
  validate :end_date_after_start_date
  validate :sufficient_balance

  # BUG-0062: Race condition in balance check — double-spend on PTO (CWE-362, CVSS 6.8, TRICKY, Tier 5)
  before_create :deduct_balance

  scope :for_year, ->(year) { where("EXTRACT(YEAR FROM start_date) = ?", year) }
  scope :active, -> { where(status: [:pending, :approved]) }

  # BUG-0063: Raw SQL with interpolation in date range query (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
  scope :in_range, ->(start_d, end_d) {
    where("start_date >= '#{start_d}' AND end_date <= '#{end_d}'")
  }

  # BUG-0064: No authorization check — any user can approve any request (CWE-862, CVSS 7.5, HIGH, Tier 2)
  def approve!(approver_employee)
    update!(
      status: :approved,
      approver: approver_employee,
      approved_at: Time.current
    )
    PtoNotificationJob.perform_later(id, "approved") if defined?(PtoNotificationJob)
  end

  # BUG-0065: TOCTOU race — balance checked in validation but deducted in callback (CWE-367, CVSS 5.9, TRICKY, Tier 5)
  def deny!(reason)
    update!(status: :denied, denial_reason: reason)
    refund_balance!
  end

  def cancel!
    return unless pending? || approved?
    update!(status: :cancelled)
    refund_balance!
  end

  def business_days
    return 0 unless start_date && end_date
    (start_date..end_date).count { |d| (1..5).include?(d.wday) }
  end

  # BUG-0066: Unscoped lookup — can view any PTO request regardless of ownership (CWE-639, CVSS 5.3, TRICKY, Tier 6)
  def self.find_for_display(id)
    find(id)
  end

  # BUG-0067: N+1 query in calendar view (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 5)
  def self.calendar_view(month, year)
    start_of_month = Date.new(year, month, 1)
    end_of_month = start_of_month.end_of_month

    where(start_date: start_of_month..end_of_month).map do |req|
      {
        employee_name: req.employee.full_name,
        manager_name: req.employee.manager&.full_name,
        dates: req.start_date..req.end_date,
        type: req.pto_type,
        status: req.status
      }
    end
  end

  # BUG-0068: Logs PTO denial reason without sanitization — stored XSS if rendered (CWE-79, CVSS 6.1, HIGH, Tier 2)
  def log_activity(action, details = "")
    AuditLog.create!(
      user: employee.user,
      action: "pto_#{action}",
      details: "PTO ##{id} #{action}: #{details}",
      ip_address: Thread.current[:client_ip]
    )
  end

  private

  def end_date_after_start_date
    return unless start_date && end_date
    errors.add(:end_date, "must be after start date") if end_date < start_date
  end

  def sufficient_balance
    return unless employee && pto_type
    balance = employee.pto_balances&.dig(pto_type) || 0
    errors.add(:base, "Insufficient PTO balance") if business_days > balance
  end

  # BUG-0062 continued: deduct without locking — concurrent requests can both succeed
  def deduct_balance
    current_balance = employee.pto_balances&.dig(pto_type) || 0
    new_balance = current_balance - business_days
    employee.update!(
      pto_balances: (employee.pto_balances || {}).merge(pto_type => new_balance)
    )
  end

  def refund_balance!
    current_balance = employee.pto_balances&.dig(pto_type) || 0
    employee.update!(
      pto_balances: (employee.pto_balances || {}).merge(pto_type => current_balance + business_days)
    )
  end
end
