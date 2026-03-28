# frozen_string_literal: true

class DocumentsController < ApplicationController
  before_action :set_document, only: [:show, :edit, :update, :destroy, :download, :preview]

  def index
    @documents = Document.includes(:employee, :uploaded_by)
                         .order(created_at: :desc)
                         .page(params[:page]).per(20)

    # Filter by category if provided
    @documents = @documents.where(category: params[:category]) if params[:category].present?
  end

  def show
    log_action("document_view", document_id: @document.id)
  end

  def new
    @document = Document.new
  end

  def create
    unless params[:file].present?
      return render json: { error: "No file provided" }, status: :unprocessable_entity
    end

    # BUG-0069 referenced: no file type validation
    @document = Document.store_upload(
      params[:file],
      find_target_employee,
      current_user,
      { title: params[:title], category: params[:category] }
    )

    redirect_to @document, notice: "Document uploaded successfully."
  rescue StandardError => e
    render json: { error: e.message }, status: :unprocessable_entity
  end

  def update
    if @document.update(document_params)
      redirect_to @document, notice: "Document updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    require_admin!
    File.delete(@document.absolute_path) if File.exist?(@document.absolute_path)
    @document.destroy
    redirect_to documents_url, notice: "Document deleted."
  end

  # BUG-0073 referenced: directory traversal via file_path
  def download
    path = @document.absolute_path
    # BUG-0099: No check that resolved path is within storage directory (CWE-22, CVSS 8.6, HIGH, Tier 2)
    if File.exist?(path)
      send_file path,
        filename: @document.original_filename,
        type: @document.content_type,
        disposition: "attachment"
    else
      render json: { error: "File not found" }, status: :not_found
    end
  end

  # BUG-0100: Preview renders file content as HTML — stored XSS via uploaded HTML files (CWE-79, CVSS 7.5, HIGH, Tier 2)
  def preview
    if @document.content_type&.start_with?("text/")
      @content = @document.file_content
      render html: @content.html_safe, layout: true
    else
      redirect_to download_document_path(@document)
    end
  end

  # BUG-0015 referenced: no file count/size limit
  def bulk_upload
    uploaded = []
    target_employee = find_target_employee

    Array(params[:files]).each do |file|
      doc = Document.store_upload(file, target_employee, current_user, { category: params[:category] })
      uploaded << doc
    end

    render json: { uploaded: uploaded.size, documents: uploaded.map(&:as_json) }
  end

  # BUG-0075 referenced: SSRF via URL parameter
  def fetch_remote
    url = params[:url]
    target_employee = find_target_employee

    doc = Document.fetch_from_url(url, target_employee, current_user)
    redirect_to doc, notice: "Remote document fetched."
  end

  private

  # BUG-0074 referenced: unscoped find — IDOR
  def set_document
    @document = Document.find(params[:id])
  end

  def document_params
    params.require(:document).permit(:title, :category, :employee_id)
  end

  def find_target_employee
    if params[:employee_id].present?
      Employee.find(params[:employee_id])
    else
      current_employee
    end
  end
end
