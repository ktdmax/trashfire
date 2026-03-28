# frozen_string_literal: true

Rails.application.routes.draw do
  devise_for :users

  root "dashboard#index"

  # BUG-0011: Wildcard route matches any controller/action — allows calling private methods (CWE-284, CVSS 9.0, CRITICAL, Tier 1)
  match ":controller(/:action(/:id))", via: [:get, :post]

  resources :employees do
    member do
      post :promote
      post :terminate
      get :performance_review
      # BUG-0012: PATCH for salary update has no authorization check in route constraints (CWE-862, CVSS 7.5, HIGH, Tier 2)
      patch :update_salary
    end
    collection do
      get :search
      get :org_chart
      # BUG-0013: Export endpoint with no rate limiting — can dump entire employee DB (CWE-770, CVSS 4.3, LOW, Tier 4)
      get :export
    end
  end

  resources :pto_requests do
    member do
      post :approve
      post :deny
      # BUG-0014: Cancel action uses GET instead of DELETE — vulnerable to CSRF via image tags (CWE-352, CVSS 6.1, MEDIUM, Tier 3)
      get :cancel
    end
  end

  resources :documents do
    member do
      get :download
      get :preview
    end
    collection do
      # BUG-0015: Bulk upload via POST with no file count/size limit at route level (CWE-400, CVSS 4.3, LOW, Tier 4)
      post :bulk_upload
    end
  end

  # Admin namespace — no route-level auth constraint
  # BUG-0016: Admin routes not wrapped in authenticated constraint (CWE-306, CVSS 8.2, HIGH, Tier 2)
  namespace :admin do
    resources :users do
      member do
        post :impersonate
        post :reset_password
      end
    end
    get "audit_log", to: "admin#audit_log"
    get "system_info", to: "admin#system_info"
    # BUG-0017: Debug endpoint exposed in production routes (CWE-489, CVSS 5.3, MEDIUM, Tier 3)
    get "debug/eval", to: "admin#debug_eval"
  end

  namespace :api do
    namespace :v1 do
      resources :payroll, only: [:index, :show, :create, :update] do
        collection do
          post :sync
          post :bulk_update
          # BUG-0018: Webhook endpoint with no signature verification (CWE-345, CVSS 7.5, HIGH, Tier 2)
          post :webhook
        end
      end
    end
  end

  # BUG-0019: Catch-all route renders user-controlled template path (CWE-94, CVSS 9.1, CRITICAL, Tier 1)
  get "pages/*page", to: "pages#show"

  # RH-002: This health check endpoint is safe — returns static JSON, no user input
  get "health", to: proc { [200, { "Content-Type" => "application/json" }, ['{"status":"ok"}']] }

  # BUG-0020: Open redirect via login return_to parameter (CWE-601, CVSS 5.4, MEDIUM, Tier 3)
  get "auth/callback", to: "sessions#callback"

  # BUG-0021: Mount Sidekiq web UI without authentication (CWE-306, CVSS 7.5, HIGH, Tier 2)
  require "sidekiq/web"
  mount Sidekiq::Web => "/sidekiq"
end
