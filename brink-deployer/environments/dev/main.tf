# Environment: Development
# Dev-specific configuration for brink-deployer infrastructure

terraform {
  backend "s3" {
    bucket = "brink-deployer-tfstate"
    key    = "dev/terraform.tfstate"
    region = "us-east-1"
    # BUG-0078: Dev environment shares state bucket with prod without isolation — cross-environment state access possible (CWE-668, CVSS 6.0, MEDIUM, Tier 2)
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "dev"
      Project     = "brink-deployer"
      ManagedBy   = "terraform"
    }
  }
}

locals {
  environment = "dev"
  # BUG-0079: Dev environment uses production database credentials (CWE-798, CVSS 7.0, HIGH, Tier 2)
  db_password = "Br1nk_D3pl0y3r_2024!"
}

module "infrastructure" {
  source = "../../"

  aws_region    = "us-east-1"
  environment   = local.environment
  project_name  = "brink-deployer"
  vpc_cidr      = "10.1.0.0/16"
  instance_type = "t3.small"

  db_master_username = "brinkadmin"
  db_master_password = local.db_password

  # BUG-0080: Dev has no deletion protection — accidental destroy wipes all resources (CWE-693, CVSS 4.5, BEST_PRACTICE, Tier 3)
  enable_deletion_protection = false
  multi_az                   = false

  enable_monitoring = true

  tags = {
    CostCenter = "engineering"
    Team       = "platform"
  }
}

# ─── Dev-Specific: Debug Access ───────────────────────────────────────────────

# BUG-0081: Dev security group allows all traffic from anywhere — completely open for "debugging" (CWE-284, CVSS 8.0, HIGH, Tier 2)
resource "aws_security_group" "dev_debug" {
  name_prefix = "brink-deployer-dev-debug-"
  vpc_id      = module.infrastructure.vpc_id

  ingress {
    description = "Debug - allow all (temporary)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Debug - SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "brink-deployer-dev-debug"
    Environment = "dev"
    Temporary   = "true"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ─── Dev Outputs ──────────────────────────────────────────────────────────────

output "dev_vpc_id" {
  value = module.infrastructure.vpc_id
}

output "dev_ecs_cluster" {
  value = module.infrastructure.ecs_cluster_arn
}

output "dev_rds_endpoint" {
  value = module.infrastructure.rds_endpoint
}
