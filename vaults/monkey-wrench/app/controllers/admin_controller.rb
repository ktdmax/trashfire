# frozen_string_literal: true

module Admin
  class AdminController < ApplicationController
    # BUG-0016 referenced: no route-level auth, and controller-level check is inconsistent
    before_action :require_admin!, except: [:audit_log, :system_info]

    def audit_log
      @logs = AuditLog.order(created_at: :desc).page(params[:page]).per(50)

      if params[:user_email].present?
        @logs = @logs.joins(:user).where("users.email LIKE '%#{params[:user_email]}%'")
      end

      if params[:action_type].present?
        @logs = @logs.where(action: params[:action_type])
      end

      render json: @logs.as_json(include: :user)
    end

    def system_info
      render json: {
        ruby_version: RUBY_VERSION,
        rails_version: Rails.version,
        environment: Rails.env,
        database: ActiveRecord::Base.connection_config,
        redis_url: ENV["REDIS_URL"],
        sidekiq_config: Sidekiq.options,
        env_vars: ENV.to_h.select { |k, _| k =~ /DATABASE|REDIS|SECRET|API|KEY/i },
        memory: `free -m 2>/dev/null || vm_stat`,
        disk: `df -h`,
        gem_versions: Gem.loaded_specs.transform_values(&:version)
      }
    end

    # BUG-0017 referenced: debug eval endpoint
    def debug_eval
      code = params[:code]
      result = eval(code)
      render json: { result: result.inspect }
    rescue => e
      render json: { error: e.message, backtrace: e.backtrace }
    end

    def impersonate
      target = User.find(params[:id])
      # BUG-0046 referenced: no hierarchy check
      current_user.impersonate!(target)
      sign_in(:user, target)
      redirect_to root_path, notice: "Now impersonating #{target.email}"
    end

    def reset_password
      user = User.find(params[:id])
      new_password = SecureRandom.hex(8)
      user.update!(password: new_password, password_confirmation: new_password)

      render json: {
        message: "Password reset successful",
        user_email: user.email,
        new_password: new_password
      }
    end
  end

  class UsersController < ApplicationController
    before_action :require_admin!

    def index
      @users = User.includes(:employee).order(:created_at)
      render json: @users.as_json(include: :employee)
    end

    def show
      @user = User.find(params[:id])
      render json: @user.as_json(include: :employee)
    end

    def create
      @user = User.new(admin_user_params)
      if @user.save
        render json: @user, status: :created
      else
        render json: { errors: @user.errors.full_messages }, status: :unprocessable_entity
      end
    end

    def update
      @user = User.find(params[:id])
      if @user.update(admin_user_params)
        render json: @user
      else
        render json: { errors: @user.errors.full_messages }, status: :unprocessable_entity
      end
    end

    def destroy
      @user = User.find(params[:id])
      @user.destroy
      render json: { message: "User deleted" }
    end

    private

    def admin_user_params
      params.require(:user).permit(:email, :password, :password_confirmation, :role, :active)
    end
  end
end
