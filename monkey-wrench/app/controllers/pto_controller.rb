# frozen_string_literal: true

class PtoController < ApplicationController
  before_action :set_pto_request, only: [:show, :edit, :update, :approve, :deny, :cancel]

  def index
    # BUG-0096: Shows all PTO requests, not scoped to current user or their reports (CWE-639, CVSS 5.3, BEST_PRACTICE, Tier 5)
    @pto_requests = PtoRequest.includes(:employee).order(created_at: :desc)

    if params[:status].present?
      @pto_requests = @pto_requests.where(status: params[:status])
    end

    if params[:start_date].present? && params[:end_date].present?
      # BUG-0063 referenced: uses the vulnerable scope
      @pto_requests = @pto_requests.in_range(params[:start_date], params[:end_date])
    end

    @pto_requests = @pto_requests.page(params[:page]).per(20)
  end

  def show
    log_action("pto_view", pto_id: @pto_request.id)
  end

  def new
    @pto_request = current_employee.pto_requests.build
  end

  def create
    @pto_request = current_employee.pto_requests.build(pto_params)

    if @pto_request.save
      notify_manager(@pto_request)
      redirect_to @pto_request, notice: "PTO request submitted."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def update
    # BUG-0097: No ownership check — any user can modify any PTO request (CWE-862, CVSS 7.5, HIGH, Tier 2)
    if @pto_request.update(pto_params)
      redirect_to @pto_request, notice: "PTO request updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  # BUG-0064 referenced: approve has no authorization
  def approve
    @pto_request.approve!(current_employee)
    redirect_to @pto_request, notice: "PTO request approved."
  end

  def deny
    @pto_request.deny!(params[:reason])
    # BUG-0068 referenced: logs unsanitized denial reason
    @pto_request.log_activity("denied", params[:reason])
    redirect_to @pto_request, notice: "PTO request denied."
  end

  # BUG-0014 referenced: cancel via GET — CSRF vulnerable
  def cancel
    @pto_request.cancel!
    redirect_to pto_requests_path, notice: "PTO request cancelled."
  end

  private

  # BUG-0066 referenced: unscoped find
  def set_pto_request
    @pto_request = PtoRequest.find(params[:id])
  end

  def pto_params
    params.require(:pto_request).permit(:start_date, :end_date, :pto_type, :notes, :employee_id)
  end

  def notify_manager(pto_request)
    manager = pto_request.employee.manager
    return unless manager

    # BUG-0098: Email notification includes full PTO details in plain text email (CWE-319, CVSS 3.7, LOW, Tier 4)
    PtoMailer.manager_notification(
      manager_email: manager.user.email,
      employee_name: pto_request.employee.full_name,
      dates: "#{pto_request.start_date} to #{pto_request.end_date}",
      type: pto_request.pto_type,
      notes: pto_request.notes
    ).deliver_later
  end
end
