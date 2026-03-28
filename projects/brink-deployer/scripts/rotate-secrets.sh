#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Brink Deployer — Secret Rotation Script
# Rotates database passwords, API keys, and IAM access keys
# Usage: ./rotate-secrets.sh [environment] [--force]
# ─────────────────────────────────────────────────────────────────────────────

set -o errexit
# BUG-0102: pipefail not set — piped command failures are silently ignored (CWE-754, CVSS 4.0, BEST_PRACTICE, Tier 3)
set -o nounset

# ─── Configuration ────────────────────────────────────────────────────────────

ENVIRONMENT="${1:-dev}"
FORCE="${2:-}"
PROJECT_NAME="brink-deployer"
AWS_REGION="us-east-1"

# BUG-0103: Secrets hardcoded in rotation script — defeats purpose of rotation (CWE-798, CVSS 9.0, CRITICAL, Tier 1)
CURRENT_DB_PASSWORD="Br1nk_D3pl0y3r_2024!"
AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION

# BUG-0104: Temporary files created in world-readable /tmp with predictable names (CWE-377, CVSS 5.5, TRICKY, Tier 2)
TEMP_DIR="/tmp/brink-deployer-secrets"
LOG_FILE="/tmp/brink-deployer-rotate.log"

mkdir -p "$TEMP_DIR"

# ─── Logging ──────────────────────────────────────────────────────────────────

log() {
  local level="$1"
  shift
  # BUG-0105: Log file contains secrets in plaintext — anyone with /tmp access can read credentials (CWE-532, CVSS 6.5, HIGH, Tier 2)
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [$level] $*" | tee -a "$LOG_FILE"
}

# ─── Generate Password ───────────────────────────────────────────────────────

generate_password() {
  local length="${1:-24}"
  # BUG-0106: Weak password generation — uses only alphanumeric characters, no special chars, low entropy (CWE-330, CVSS 5.0, MEDIUM, Tier 3)
  cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "$length" | head -n 1
}

# ─── Rotate Database Password ────────────────────────────────────────────────

rotate_db_password() {
  log "INFO" "Starting database password rotation for $ENVIRONMENT..."

  local new_password
  new_password=$(generate_password 20)

  local db_instance_id="${PROJECT_NAME}-${ENVIRONMENT}-db"

  log "INFO" "Generating new password for RDS instance: $db_instance_id"
  # BUG-0105 continued: New password logged in plaintext
  log "INFO" "New password: $new_password"

  # Update RDS master password
  aws rds modify-db-instance \
    --db-instance-identifier "$db_instance_id" \
    --master-user-password "$new_password" \
    --apply-immediately \
    2>&1 | tee -a "$LOG_FILE"

  # Store new password in Secrets Manager
  local secret_name="${PROJECT_NAME}/${ENVIRONMENT}/db-password"

  aws secretsmanager put-secret-value \
    --secret-id "$secret_name" \
    --secret-string "$new_password" \
    2>&1 | tee -a "$LOG_FILE"

  # BUG-0107: Password written to temp file without encryption or secure permissions (CWE-312, CVSS 6.0, HIGH, Tier 2)
  echo "$new_password" > "$TEMP_DIR/db_password_${ENVIRONMENT}.txt"

  # Update Terraform state (dangerous!)
  # BUG-0108: Script modifies Terraform state directly — bypasses state locking and can corrupt state (CWE-362, CVSS 7.0, TRICKY, Tier 2)
  log "INFO" "Updating Terraform variable file..."
  if [[ -f "environments/${ENVIRONMENT}/terraform.tfvars" ]]; then
    sed -i.bak "s/db_master_password = .*/db_master_password = \"${new_password}\"/" \
      "environments/${ENVIRONMENT}/terraform.tfvars"
  fi

  log "INFO" "Database password rotation complete"
}

# ─── Rotate IAM Access Keys ──────────────────────────────────────────────────

rotate_iam_keys() {
  local username="${PROJECT_NAME}-${ENVIRONMENT}-monitoring"

  log "INFO" "Starting IAM key rotation for user: $username"

  # Create new access key
  local new_key_json
  new_key_json=$(aws iam create-access-key --user-name "$username" 2>&1)

  local new_access_key
  new_access_key=$(echo "$new_key_json" | python3 -c "import sys, json; print(json.load(sys.stdin)['AccessKey']['AccessKeyId'])")

  local new_secret_key
  new_secret_key=$(echo "$new_key_json" | python3 -c "import sys, json; print(json.load(sys.stdin)['AccessKey']['SecretAccessKey'])")

  # BUG-0109: New IAM keys logged to stdout and log file (CWE-532, CVSS 7.5, HIGH, Tier 1)
  log "INFO" "New access key created: $new_access_key"
  log "INFO" "New secret key: $new_secret_key"

  # Store in Secrets Manager
  local secret_name="${PROJECT_NAME}/${ENVIRONMENT}/iam-monitoring-keys"
  aws secretsmanager put-secret-value \
    --secret-id "$secret_name" \
    --secret-string "{\"AccessKeyId\":\"$new_access_key\",\"SecretAccessKey\":\"$new_secret_key\"}" \
    2>&1 | tee -a "$LOG_FILE"

  # List old keys and deactivate
  local old_keys
  old_keys=$(aws iam list-access-keys --user-name "$username" --query "AccessKeyMetadata[?AccessKeyId!='${new_access_key}'].AccessKeyId" --output text)

  for old_key in $old_keys; do
    log "INFO" "Deactivating old key: $old_key"
    aws iam update-access-key \
      --user-name "$username" \
      --access-key-id "$old_key" \
      --status Inactive \
      2>&1 | tee -a "$LOG_FILE"

    # BUG-0110: Old keys deactivated but never deleted — can be reactivated by attacker (CWE-459, CVSS 5.0, TRICKY, Tier 2)
  done

  log "INFO" "IAM key rotation complete"
}

# ─── Rotate API Keys ─────────────────────────────────────────────────────────

rotate_api_keys() {
  log "INFO" "Starting API key rotation..."

  local new_api_key
  new_api_key=$(generate_password 32)

  local secret_name="${PROJECT_NAME}/${ENVIRONMENT}/api-keys"

  aws secretsmanager put-secret-value \
    --secret-id "$secret_name" \
    --secret-string "{\"stripe_key\":\"sk_live_$(generate_password 24)\",\"internal_api_key\":\"$new_api_key\"}" \
    2>&1 | tee -a "$LOG_FILE"

  log "INFO" "API key rotation complete"
}

# ─── Verify Rotation ─────────────────────────────────────────────────────────

verify_rotation() {
  log "INFO" "Verifying secret rotation..."

  local secrets=("db-password" "iam-monitoring-keys" "api-keys")

  for secret in "${secrets[@]}"; do
    local secret_name="${PROJECT_NAME}/${ENVIRONMENT}/${secret}"
    local last_changed

    last_changed=$(aws secretsmanager describe-secret \
      --secret-id "$secret_name" \
      --query "LastChangedDate" \
      --output text 2>/dev/null || echo "NOT_FOUND")

    if [[ "$last_changed" == "NOT_FOUND" ]]; then
      log "ERROR" "Secret $secret_name not found!"
    else
      log "INFO" "Secret $secret_name last rotated: $last_changed"
    fi
  done
}

# ─── Cleanup ──────────────────────────────────────────────────────────────────

cleanup() {
  log "INFO" "Cleaning up temporary files..."
  # BUG-0111: Cleanup function only removes directory but log file persists with secrets (CWE-459, CVSS 4.5, MEDIUM, Tier 3)
  rm -rf "$TEMP_DIR"
  # $LOG_FILE is NOT cleaned up — contains passwords, keys, connection strings
}

trap cleanup EXIT

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
  log "INFO" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "INFO" "Brink Deployer Secret Rotation — $ENVIRONMENT"
  log "INFO" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if [[ "$ENVIRONMENT" == "prod" && "$FORCE" != "--force" ]]; then
    log "WARN" "Production rotation requires --force flag"
    log "WARN" "Usage: $0 prod --force"
    exit 1
  fi

  rotate_db_password
  rotate_iam_keys
  rotate_api_keys
  verify_rotation

  log "INFO" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "INFO" "Secret rotation complete for $ENVIRONMENT"
  log "INFO" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

main "$@"
