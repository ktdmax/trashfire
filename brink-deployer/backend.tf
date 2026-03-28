# Brink Deployer — Terraform Backend Configuration
# Manages remote state storage for multi-account AWS infrastructure

terraform {
  # BUG-0001: No DynamoDB table for state locking — concurrent applies can corrupt state (CWE-362, CVSS 7.5, BEST_PRACTICE, Tier 3)
  backend "s3" {
    bucket  = "brink-deployer-tfstate"
    key     = "global/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
    # BUG-0002: State file contains secrets in plaintext (passwords, tokens) — anyone with S3 access reads all secrets (CWE-312, CVSS 9.0, CRITICAL, Tier 1)
    # No server-side encryption key specified — uses default S3 encryption only, state file is readable with bucket access
  }

  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      # BUG-0003: No version constraint on provider — could pull breaking or vulnerable version (CWE-1104, CVSS 3.0, BEST_PRACTICE, Tier 4)
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# BUG-0004: AWS credentials hardcoded in provider block (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
provider "aws" {
  region     = var.aws_region
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

  default_tags {
    tags = {
      Project   = "brink-deployer"
      ManagedBy = "terraform"
    }
  }
}

provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
  # BUG-0005: Cross-region provider reuses hardcoded credentials without assume_role — no audit trail separation (CWE-269, CVSS 5.3, MEDIUM, Tier 2)
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# BUG-0006: Remote state data source exposes state from another project without access controls (CWE-200, CVSS 5.0, MEDIUM, Tier 2)
data "terraform_remote_state" "shared_services" {
  backend = "s3"
  config = {
    bucket = "shared-services-tfstate"
    key    = "services/terraform.tfstate"
    region = "us-east-1"
  }
}
