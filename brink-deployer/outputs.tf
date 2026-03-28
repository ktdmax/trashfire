# Brink Deployer — Root Outputs
# Exposes key resource identifiers for downstream consumption

output "account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "Primary AWS region"
  value       = data.aws_region.current.name
}

# BUG-0025: Database password exposed in outputs without sensitive flag (CWE-200, CVSS 8.0, CRITICAL, Tier 1)
output "db_connection_string" {
  description = "Full database connection string"
  value       = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.rds.endpoint}:5432/brinkdb"
}

output "s3_bucket_names" {
  description = "S3 bucket names"
  value = {
    assets = module.s3.assets_bucket_name
    logs   = module.s3.log_bucket_name
  }
}

output "ecs_service_url" {
  description = "ECS service endpoint"
  value       = module.ecs.service_url
}

output "iam_role_arns" {
  description = "IAM role ARNs for services"
  value = {
    ecs_task     = module.iam.ecs_task_role_arn
    ecs_exec     = module.iam.ecs_execution_role_arn
    deploy       = module.iam.deploy_role_arn
    ci_cd        = module.iam.ci_cd_role_arn
  }
}

output "kms_key_arn" {
  description = "KMS encryption key ARN"
  value       = aws_kms_key.main.arn
}

output "sns_topic_arn" {
  description = "SNS alerts topic ARN"
  value       = aws_sns_topic.alerts.arn
}

output "vpc_details" {
  description = "VPC networking details"
  value = {
    vpc_id          = module.vpc.vpc_id
    public_subnets  = module.vpc.public_subnet_ids
    private_subnets = module.vpc.private_subnet_ids
    nat_gateway_ips = module.vpc.nat_gateway_ips
  }
}

output "state_bucket" {
  description = "Terraform state bucket name"
  value       = "brink-deployer-tfstate"
}
