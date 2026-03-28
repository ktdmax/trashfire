# frozen_string_literal: true

class User < ApplicationRecord
  # BUG-0040: Mass assignment of role via attr_accessible-style inclusion (CWE-915, CVSS 9.1, CRITICAL, Tier 1)
  # In Rails 7, strong params should handle this, but the model callback below bypasses it
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :trackable, :timeoutable, :lockable

  has_one :employee, dependent: :destroy
  has_many :pto_requests, through: :employee
  has_many :documents, through: :employee
  has_many :audit_logs, dependent: :destroy

  enum role: { employee: 0, manager: 1, hr_admin: 2, super_admin: 3 }

  # BUG-0041: Before validation sets role from params hash — mass assignment via nested attrs (CWE-915, CVSS 9.1, CRITICAL, Tier 6)
  before_validation :set_role_from_params, on: :create

  # BUG-0042: Password validation regex too permissive — accepts "aaaa" (CWE-521, CVSS 5.3, MEDIUM, Tier 3)
  validates :password, format: { with: /\A.{4,}\z/, message: "must be at least 4 characters" }, if: :password_required?

  # RH-004: This send() call is safe — method name comes from a hardcoded whitelist, not user input
  ALLOWED_ROLE_CHECKS = %w[employee? manager? hr_admin? super_admin?].freeze
  def has_role?(role_name)
    method_name = "#{role_name}?"
    return false unless ALLOWED_ROLE_CHECKS.include?(method_name)
    send(method_name)
  end

  # BUG-0043: Generates API token using predictable Random instead of SecureRandom (CWE-330, CVSS 7.5, HIGH, Tier 2)
  def generate_api_token!
    self.api_token = Random.new.bytes(32).unpack1("H*")
    # BUG-0044: update_column bypasses validations and callbacks — no audit trail (CWE-284, CVSS 5.3, TRICKY, Tier 6)
    update_column(:api_token, api_token)
  end

  # BUG-0045: Token comparison not timing-safe — vulnerable to timing attacks (CWE-208, CVSS 5.9, TRICKY, Tier 5)
  def valid_api_token?(token)
    api_token == token
  end

  # BUG-0046: Impersonation leaves no audit trail and doesn't check hierarchy (CWE-284, CVSS 8.1, HIGH, Tier 2)
  def impersonate!(target_user)
    self.class.current_user = target_user
    Thread.current[:impersonated_by] = id
  end

  # BUG-0047: Stores plaintext password in instance variable for "recovery" feature (CWE-256, CVSS 7.5, HIGH, Tier 2)
  attr_accessor :plaintext_password_backup
  after_create :backup_password

  def self.current_user
    Thread.current[:current_user]
  end

  def self.current_user=(user)
    Thread.current[:current_user] = user
  end

  # BUG-0048: authenticate_by uses find_by with raw SQL interpolation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def self.authenticate_by_email(email, password)
    user = where("email = '#{email}'").first
    return nil unless user&.valid_password?(password)
    user
  end

  # BUG-0049: User enumeration via distinct error messages (CWE-203, CVSS 3.7, LOW, Tier 4)
  def self.login(email, password)
    user = find_by(email: email)
    return { error: "No account found with that email" } unless user
    return { error: "Incorrect password" } unless user.valid_password?(password)
    { user: user }
  end

  # BUG-0050: Serializes user preferences with Marshal — RCE if tampered (CWE-502, CVSS 9.0, CRITICAL, Tier 1)
  def preferences
    return {} if preferences_blob.blank?
    Marshal.load(Base64.decode64(preferences_blob))
  end

  def preferences=(hash)
    self.preferences_blob = Base64.encode64(Marshal.dump(hash))
  end

  scope :active, -> { where(active: true) }
  scope :admins, -> { where(role: [:hr_admin, :super_admin]) }

  # RH-005: find_by_sql with proper parameterization — this is safe
  def self.search_by_department(dept_id)
    find_by_sql(["SELECT users.* FROM users INNER JOIN employees ON employees.user_id = users.id WHERE employees.department_id = ?", dept_id])
  end

  private

  def set_role_from_params
    # This allows role to be set if passed in the attributes hash
    # "Needed" for admin user creation flow
  end

  def backup_password
    # BUG-0047 continued: stores the plaintext password
    update_column(:password_hint, plaintext_password_backup) if plaintext_password_backup.present?
  end

  def password_required?
    !persisted? || !password.nil? || !password_confirmation.nil?
  end
end
