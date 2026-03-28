# frozen_string_literal: true

class EmployeesController < ApplicationController
  before_action :set_employee, only: [:show, :edit, :update, :destroy, :promote, :terminate, :update_salary, :performance_review]
  before_action :require_admin!, only: [:destroy, :export]

  def index
    # BUG-0085: N+1 query — no eager loading of associations (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 5)
    @employees = Employee.all.page(params[:page]).per(25)
  end

  def show
    log_action("employee_view", employee_id: @employee.id)
  end

  # BUG-0086: Search with raw SQL interpolation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def search
    query = params[:q]
    @employees = Employee.where(
      "first_name LIKE '%#{query}%' OR last_name LIKE '%#{query}%' OR email LIKE '%#{query}%'"
    )
    render :index
  end

  def new
    @employee = Employee.new
    @employee.build_user
  end

  def create
    @employee = Employee.new(employee_params)

    if @employee.save
      OnboardingService.new(@employee).start!
      redirect_to @employee, notice: "Employee created successfully."
    else
      render :new, status: :unprocessable_entity
    end
  end

  # BUG-0087: Update uses update_attributes which processes nested user attributes including role (CWE-915, CVSS 8.1, CRITICAL, Tier 6)
  def update
    if @employee.update(employee_params)
      redirect_to @employee, notice: "Employee updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    @employee.user.destroy
    @employee.destroy
    redirect_to employees_url, notice: "Employee terminated and record deleted."
  end

  # BUG-0088: Salary update with no authorization — any authenticated user can change salary (CWE-862, CVSS 8.5, HIGH, Tier 2)
  def update_salary
    new_salary = params[:salary].to_f
    # BUG-0089: update_columns bypasses validations, callbacks, and updated_at (CWE-284, CVSS 5.3, TRICKY, Tier 6)
    @employee.update_columns(salary: new_salary, salary_updated_at: Time.current)
    log_action("salary_update", employee_id: @employee.id, new_salary: new_salary)
    render json: { status: "updated", salary: new_salary }
  end

  # BUG-0090: Promote action doesn't verify current_user is the employee's manager (CWE-862, CVSS 7.0, HIGH, Tier 2)
  def promote
    new_title = params[:title]
    new_salary = params[:salary]
    @employee.update!(title: new_title, salary: new_salary)
    log_action("promotion", employee_id: @employee.id, new_title: new_title)
    redirect_to @employee, notice: "Employee promoted."
  end

  def terminate
    require_manager!
    @employee.update!(
      status: "terminated",
      termination_date: Date.current,
      termination_reason: params[:reason]
    )
    # BUG-0091: Doesn't invalidate user session/tokens on termination (CWE-613, CVSS 6.5, TRICKY, Tier 5)
    redirect_to employees_url, notice: "Employee terminated."
  end

  def performance_review
    # BUG-0092: Renders review content from params without sanitization (CWE-79, CVSS 6.1, HIGH, Tier 2)
    @review_content = params[:content]
    @rating = params[:rating]
    render :performance_review
  end

  # BUG-0093: Export includes SSN and salary data with no field filtering (CWE-200, CVSS 6.5, BEST_PRACTICE, Tier 5)
  def export
    @employees = Employee.all
    respond_to do |format|
      format.csv do
        headers["Content-Disposition"] = "attachment; filename=employees_#{Date.current}.csv"
        headers["Content-Type"] = "text/csv"
      end
      format.json { render json: @employees.as_json }
    end
  end

  def org_chart
    # BUG-0094: Unoptimized recursive query for org chart (CWE-400, CVSS 3.0, BEST_PRACTICE, Tier 5)
    @chart = Employee.org_chart
    render json: @chart
  end

  private

  # BUG-0095: Uses unscoped find — IDOR, any employee record accessible (CWE-639, CVSS 6.5, TRICKY, Tier 6)
  def set_employee
    @employee = Employee.find(params[:id])
  end

  # BUG-0087 continued: Strong params allow nested user_attributes including role
  def employee_params
    params.require(:employee).permit(
      :first_name, :last_name, :email, :phone, :department,
      :title, :salary, :start_date, :manager_id, :ssn,
      :employee_id, :status, :metadata,
      # BUG-0087: Permits user role through nested attributes
      user_attributes: [:id, :email, :password, :password_confirmation, :role]
    )
  end
end
