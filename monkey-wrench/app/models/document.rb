# frozen_string_literal: true

class Document < ApplicationRecord
  belongs_to :employee
  belongs_to :uploaded_by, class_name: "User"

  enum category: {
    tax_form: 0, id_verification: 1, contract: 2,
    performance_review: 3, disciplinary: 4, benefits: 5, other: 6
  }

  validates :title, :category, presence: true
  validates :file_path, presence: true

  # BUG-0069: No file type validation — allows upload of .exe, .sh, .rb files (CWE-434, CVSS 7.5, HIGH, Tier 2)
  # Should validate: validates :content_type, inclusion: { in: %w[application/pdf image/png image/jpeg] }

  # BUG-0070: Path traversal in file storage — user controls filename (CWE-22, CVSS 8.1, HIGH, Tier 2)
  before_save :set_file_path

  # BUG-0071: Stores original filename without sanitization (CWE-22, CVSS 6.5, MEDIUM, Tier 3)
  def self.store_upload(file, employee, uploaded_by, attrs = {})
    doc = new(
      employee: employee,
      uploaded_by: uploaded_by,
      title: attrs[:title] || file.original_filename,
      category: attrs[:category] || :other,
      original_filename: file.original_filename,
      content_type: file.content_type,
      file_size: file.size
    )
    doc.save_file!(file)
    doc.save!
    doc
  end

  # BUG-0072: File read with user-controlled path — arbitrary file read (CWE-22, CVSS 8.6, HIGH, Tier 2)
  def file_content
    File.read(file_path)
  end

  # BUG-0073: send_file with user-controlled path — directory traversal (CWE-22, CVSS 8.6, HIGH, Tier 2)
  def absolute_path
    Rails.root.join("storage", "documents", file_path).to_s
  end

  # BUG-0074: Unscoped document access — IDOR (CWE-639, CVSS 6.5, TRICKY, Tier 6)
  def self.find_for_download(document_id)
    find(document_id)
  end

  def save_file!(uploaded_file)
    dir = Rails.root.join("storage", "documents", employee_id.to_s)
    FileUtils.mkdir_p(dir)
    # BUG-0070 continued: uses original filename directly
    dest = File.join(dir.to_s, original_filename)
    File.open(dest, "wb") { |f| f.write(uploaded_file.read) }
    self.file_path = File.join(employee_id.to_s, original_filename)
  end

  # BUG-0075: SSRF via URL fetch for remote documents (CWE-918, CVSS 7.4, HIGH, Tier 2)
  def self.fetch_from_url(url, employee, uploaded_by)
    require "open-uri"
    content = URI.open(url).read
    filename = File.basename(URI.parse(url).path)

    doc = new(
      employee: employee,
      uploaded_by: uploaded_by,
      title: filename,
      category: :other,
      original_filename: filename,
      content_type: "application/octet-stream",
      file_size: content.bytesize
    )

    dir = Rails.root.join("storage", "documents", employee.id.to_s)
    FileUtils.mkdir_p(dir)
    File.open(File.join(dir.to_s, filename), "wb") { |f| f.write(content) }
    doc.file_path = File.join(employee.id.to_s, filename)
    doc.save!
    doc
  end

  # BUG-0076: Renders document metadata as YAML — can inject YAML directives (CWE-502, CVSS 6.5, MEDIUM, Tier 3)
  def to_yaml_export
    YAML.dump({
      "id" => id,
      "title" => title,
      "employee" => employee.full_name,
      "category" => category,
      "uploaded_at" => created_at.iso8601
    })
  end

  # RH-006: YAML.safe_load is used here — this is safe against deserialization attacks
  def self.import_from_yaml(yaml_string)
    data = YAML.safe_load(yaml_string, permitted_classes: [Date, Time])
    new(
      title: data["title"],
      category: data["category"]
    )
  end

  private

  def set_file_path
    return if file_path.present? && !original_filename_changed?
    self.file_path = File.join(employee_id.to_s, original_filename.to_s)
  end
end
