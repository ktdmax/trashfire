# Brink Deployer — Root Variables
# Input variables for multi-account AWS infrastructure provisioner

variable "aws_region" {
  description = "Primary AWS region for deployment"
  type        = string
  default     = "us-east-1"
  # BUG-0007: No validation block on region — arbitrary region strings accepted (CWE-20, CVSS 3.0, BEST_PRACTICE, Tier 4)
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  type    = string
  default = "brink-deployer"
}

# BUG-0008: Database password as variable with default — stored in state and plan output (CWE-798, CVSS 8.5, CRITICAL, Tier 1)
variable "db_master_password" {
  description = "Master password for RDS instances"
  type        = string
  default     = "Br1nk_D3pl0y3r_2024!"
  # Missing: sensitive = true
}

variable "db_master_username" {
  description = "Master username for RDS instances"
  type        = string
  default     = "brinkadmin"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed for ingress"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "instance_type" {
  description = "EC2/ECS instance type"
  type        = string
  default     = "t3.medium"
}

# BUG-0010: Hardcoded AMI ID — region-specific, won't work in other regions and becomes stale (CWE-672, CVSS 3.0, BEST_PRACTICE, Tier 4)
variable "ami_id" {
  description = "AMI ID for EC2 instances"
  type        = string
  default     = "ami-0c55b159cbfafe1f0"
}

variable "ecs_task_cpu" {
  type    = number
  default = 256
}

variable "ecs_task_memory" {
  type    = number
  default = 512
}

variable "enable_monitoring" {
  type    = bool
  default = true
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

variable "certificate_arn" {
  type    = string
  default = ""
}

variable "domain_name" {
  description = "Primary domain name"
  type        = string
  default     = "brink-deployer.example.com"
}

variable "notification_email" {
  description = "Email for SNS notifications"
  type        = string
  default     = "ops@brink-deployer.internal"
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 7
}

variable "multi_az" {
  description = "Enable Multi-AZ for RDS"
  type        = bool
  default     = false
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection on critical resources"
  type        = bool
  # BUG-0013: Deletion protection defaults to false — accidental terraform destroy wipes prod (CWE-693, CVSS 5.5, MEDIUM, Tier 3)
  default = false
}
