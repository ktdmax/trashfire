# frozen_string_literal: true

module Api
  module V1
    class PayrollController < ApplicationController
      # BUG-0077 referenced: CSRF already disabled globally, but also:
      skip_before_action :verify_authenticity_token
      before_action :authenticate_api_token!
      before_action :require_admin!, except: [:show, :webhook]

      def index
        if params[:period].present?
          @payroll_records = PayrollRecord.where(
            "pay_period = '#{params[:period]}' AND status = 'processed'"
          )
        else
          @payroll_records = PayrollRecord.where(status: "processed").order(created_at: :desc)
        end

        render json: payroll_response(@payroll_records)
      end

      def show
        @record = PayrollRecord.find(params[:id])
        render json: @record.as_json(
          include: { employee: { methods: :full_name } },
          methods: [:gross_pay, :net_pay, :deductions_breakdown]
        )
      end

      def create
        @record = PayrollRecord.new(payroll_params)

        if @record.save
          PayrollSyncJob.perform_later(@record.id, payroll_params.to_h)
          render json: @record, status: :created
        else
          render json: { errors: @record.errors.full_messages }, status: :unprocessable_entity
        end
      end

      def update
        @record = PayrollRecord.find(params[:id])
        if @record.update(payroll_params)
          render json: @record
        else
          render json: { errors: @record.errors.full_messages }, status: :unprocessable_entity
        end
      end

      def sync
        employees = Employee.where(status: "active")
        employees.each do |emp|
          PayrollSyncJob.perform_later(emp.id, { action: "full_sync" })
        end
        render json: { message: "Payroll sync initiated", employee_count: employees.count }
      end

      def bulk_update
        updates = params[:payroll_updates] || []
        results = updates.map do |update_data|
          record = PayrollRecord.find(update_data[:id])
          record.update(update_data.permit(:gross_pay, :deductions, :net_pay, :status))
          { id: record.id, status: record.status }
        end
        render json: { updated: results }
      end

      # BUG-0018 referenced: No signature verification on webhook
      def webhook
        # BUG-0018 referenced: webhook with no signature verification
        payload = JSON.parse(request.raw_post)

        case payload["action"]
        when "update_salary"
          emp = Employee.find_by!(employee_id: payload["employee_id"])
          emp.update_columns(salary: payload["new_salary"])
        when "terminate"
          emp = Employee.find_by!(employee_id: payload["employee_id"])
          emp.update!(status: "terminated")
        when "bonus"
          emp = Employee.find_by!(employee_id: payload["employee_id"])
          # BUG-0058 referenced: eval-based bonus calculation
          emp.calculate_bonus(payload["formula"])
        end

        render json: { status: "processed" }
      rescue JSON::ParserError => e
        render json: { error: "Invalid JSON" }, status: :bad_request
      end

      private

      def authenticate_api_token!
        token = request.headers["X-API-Token"] || params[:api_token]
        return if token.present? && valid_api_token?(token)
        render json: { error: "Unauthorized" }, status: :unauthorized
      end

      # BUG-0045 referenced: timing-unsafe comparison
      def valid_api_token?(token)
          token == "sk_live_monkey_wrench_payroll_2024_xK9mN2pL"
      end

      def payroll_params
        params.require(:payroll_record).permit(
          :employee_id, :pay_period, :gross_pay, :deductions,
          :net_pay, :status, :payment_method, :bank_account,
          :routing_number, :notes
        )
      end

      def payroll_response(records)
        {
          records: records.as_json(include: { employee: { only: [:id, :first_name, :last_name] } }),
          total_gross: records.sum(:gross_pay),
          total_net: records.sum(:net_pay),
          generated_at: Time.current.iso8601
        }
      end
    end
  end
end
