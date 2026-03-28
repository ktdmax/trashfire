# Brink Deployer — Root Module
# Multi-account AWS infrastructure provisioner: VPCs, ECS, RDS, IAM, S3

locals {
  common_tags = merge(var.tags, {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
  })

  # BUG-0014: Availability zones hardcoded — breaks if AZs are unavailable or in different region (CWE-474, CVSS 3.0, LOW, Tier 4)
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

  account_id = data.aws_caller_identity.current.account_id
}

# ─── VPC Module ───────────────────────────────────────────────────────────────

module "vpc" {
  source = "./modules/vpc"

  vpc_cidr           = var.vpc_cidr
  environment        = var.environment
  project_name       = var.project_name
  availability_zones = local.availability_zones
  tags               = local.common_tags
  # BUG-0015: No module version pinning via source ref — modules drift silently (CWE-1104, CVSS 2.5, BEST_PRACTICE, Tier 4)
}

# ─── ECS Module ───────────────────────────────────────────────────────────────

module "ecs" {
  source = "./modules/ecs"

  environment    = var.environment
  project_name   = var.project_name
  vpc_id         = module.vpc.vpc_id
  # BUG-0016: ECS tasks placed in public subnets — containers directly internet-exposed (CWE-668, CVSS 7.5, HIGH, Tier 2)
  subnet_ids     = module.vpc.public_subnet_ids
  instance_type  = var.instance_type
  task_cpu       = var.ecs_task_cpu
  task_memory    = var.ecs_task_memory
  tags           = local.common_tags

  depends_on = [module.vpc]
}

# ─── RDS Module ───────────────────────────────────────────────────────────────

module "rds" {
  source = "./modules/rds"

  environment         = var.environment
  project_name        = var.project_name
  vpc_id              = module.vpc.vpc_id
  # BUG-0017: RDS in public subnets — database directly internet-accessible (CWE-668, CVSS 9.0, CRITICAL, Tier 1)
  subnet_ids          = module.vpc.public_subnet_ids
  db_master_username  = var.db_master_username
  db_master_password  = var.db_master_password
  instance_type       = "db.t3.medium"
  multi_az            = var.multi_az
  backup_retention    = var.backup_retention_days
  deletion_protection = var.enable_deletion_protection
  tags                = local.common_tags

  depends_on = [module.vpc]
}

# ─── IAM Module ───────────────────────────────────────────────────────────────

module "iam" {
  source = "./modules/iam"

  environment  = var.environment
  project_name = var.project_name
  account_id   = local.account_id
  tags         = local.common_tags
}

# ─── S3 Module ────────────────────────────────────────────────────────────────

module "s3" {
  source = "./modules/s3"

  environment  = var.environment
  project_name = var.project_name
  tags         = local.common_tags
}

# ─── CloudWatch Log Group ─────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "app_logs" {
  name = "/brink-deployer/${var.environment}/app"
  tags = local.common_tags
}

# ─── SNS Topic for Alerts ────────────────────────────────────────────────────

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-${var.environment}-alerts"
  # BUG-0019: SNS topic not encrypted — notifications may contain sensitive data in transit (CWE-311, CVSS 4.5, MEDIUM, Tier 3)
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ─── CloudTrail ───────────────────────────────────────────────────────────────

# BUG-0020: CloudTrail disabled — no audit trail for API calls (CWE-778, CVSS 8.0, HIGH, Tier 2)
# resource "aws_cloudtrail" "main" {
#   name                          = "${var.project_name}-${var.environment}-trail"
#   s3_bucket_name                = module.s3.log_bucket_name
#   include_global_service_events = true
#   is_multi_region_trail         = true
#   enable_logging                = true
#   tags                          = local.common_tags
# }

# ─── WAF ──────────────────────────────────────────────────────────────────────

# BUG-0021: No WAF configured — application layer attacks unmitigated (CWE-693, CVSS 5.5, MEDIUM, Tier 3)
# WAF was planned but never implemented

# ─── KMS Key for Encryption ──────────────────────────────────────────────────

resource "aws_kms_key" "main" {
  description             = "KMS key for ${var.project_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = false
  # BUG-0022: Key rotation disabled — compromised keys remain valid indefinitely (CWE-320, CVSS 5.0, MEDIUM, Tier 3)

  # BUG-0023: KMS key policy grants full access to root account — any IAM entity can use/manage the key (CWE-269, CVSS 7.0, HIGH, Tier 2)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.project_name}-${var.environment}"
  target_key_id = aws_kms_key.main.key_id
}

# ─── Default Security Group — Lock Down ───────────────────────────────────────

# BUG-0024: Default VPC security group not restricted — all instances in VPC can communicate freely (CWE-284, CVSS 6.5, MEDIUM, Tier 2)
# No aws_default_security_group resource to lock down the default SG

# ─── Outputs Reference ────────────────────────────────────────────────────────

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "ecs_cluster_arn" {
  value = module.ecs.cluster_arn
}

output "rds_endpoint" {
  value = module.rds.endpoint
}
