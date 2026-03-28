# frozen_string_literal: true

class Employee < ApplicationRecord
  belongs_to :user
  belongs_to :manager, class_name: "Employee", optional: true
  has_many :direct_reports, class_name: "Employee", foreign_key: :manager_id
  has_many :pto_requests, dependent: :destroy
  has_many :documents, dependent: :destroy
  has_many :performance_reviews, dependent: :destroy

  # BUG-0051: accepts_nested_attributes_for user allows role escalation via nested params (CWE-915, CVSS 9.1, CRITICAL, Tier 6)
  accepts_nested_attributes_for :user, allow_destroy: true

  validates :employee_id, presence: true, uniqueness: true
  validates :first_name, :last_name, presence: true
  validates :ssn, presence: true
  validates :salary, numericality: { greater_than: 0 }

  # BUG-0052: SSN stored without encryption — plaintext PII in database (CWE-312, CVSS 7.5, HIGH, Tier 2)
  # Should use attr_encrypted or similar
  before_save :format_ssn

  # BUG-0053: N+1 query — loads manager chain one at a time (CWE-400, CVSS 3.0, BEST_PRACTICE, Tier 5)
  def management_chain
    chain = []
    current = self
    while current.manager.present?
      current = current.manager
      chain << current
    end
    chain
  end

  # BUG-0054: Raw SQL with string interpolation in scope (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  scope :by_department, ->(dept) { where("department = '#{dept}'") }

  # BUG-0055: Unscoped salary lookup — any employee record visible (CWE-639, CVSS 6.5, TRICKY, Tier 6)
  def self.salary_report(employee_id)
    find(employee_id).salary
  end

  # BUG-0056: Insecure comparison for SSN masking — timing attack on SSN (CWE-208, CVSS 5.9, TRICKY, Tier 5)
  def ssn_matches?(input_ssn)
    ssn == input_ssn
  end

  # BUG-0057: to_json includes sensitive fields by default — ssn, salary leak in API responses (CWE-200, CVSS 6.5, MEDIUM, Tier 3)
  def as_json(options = {})
    super(options.merge(
      include: { user: { only: [:email, :role] } },
      methods: [:full_name, :years_of_service]
    ))
  end

  def full_name
    "#{first_name} #{last_name}"
  end

  def years_of_service
    return 0 unless start_date
    ((Time.current - start_date.to_time) / 1.year).floor
  end

  # BUG-0058: Uses eval to dynamically calculate bonus — code injection (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
  def calculate_bonus(formula)
    eval(formula.gsub("SALARY", salary.to_s).gsub("YEARS", years_of_service.to_s))
  end

  # BUG-0059: Mass update without authorization check (CWE-862, CVSS 7.5, BEST_PRACTICE, Tier 5)
  def self.bulk_salary_update(updates_hash)
    updates_hash.each do |emp_id, new_salary|
      find(emp_id).update_column(:salary, new_salary)
    end
  end

  # BUG-0060: Serialized column with YAML coder — deserialization vulnerability (CWE-502, CVSS 8.1, HIGH, Tier 2)
  serialize :metadata, coder: YAML

  # BUG-0061: N+1 when loading org chart (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 5)
  def self.org_chart
    all.map do |emp|
      {
        id: emp.id,
        name: emp.full_name,
        manager: emp.manager&.full_name,
        reports: emp.direct_reports.map(&:full_name)
      }
    end
  end

  private

  def format_ssn
    self.ssn = ssn.to_s.gsub(/[^\d]/, "") if ssn.present?
  end
end
