# Environment: Production
# Production-specific configuration for brink-deployer infrastructure

terraform {
  backend "s3" {
    bucket = "brink-deployer-tfstate"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
    # BUG-0083: No state locking in production — concurrent terraform applies can corrupt state (CWE-362, CVSS 7.0, BEST_PRACTICE, Tier 2)
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = "prod"
      Project     = "brink-deployer"
      ManagedBy   = "terraform"
      CostCenter  = "production"
    }
  }
}

locals {
  environment = "prod"
}

module "infrastructure" {
  source = "../../"

  aws_region    = "us-east-1"
  environment   = local.environment
  project_name  = "brink-deployer"
  vpc_cidr      = "10.0.0.0/16"
  instance_type = "t3.large"

  db_master_username = "brinkadmin"
  # BUG-0084: Production database password hardcoded in environment config (CWE-798, CVSS 9.0, CRITICAL, Tier 1)
  db_master_password = "Pr0d_Br1nk_S3cur3_2024!!"

  enable_deletion_protection = true
  multi_az                   = true
  backup_retention_days      = 30

  enable_monitoring = true

  tags = {
    CostCenter = "production"
  }
}

# ─── Production CloudFront Distribution ───────────────────────────────────────

resource "aws_cloudfront_distribution" "prod" {
  enabled = true
  comment = "Production CDN for brink-deployer"

  origin {
    domain_name = "brink-deployer-prod-assets.s3.amazonaws.com"
    origin_id   = "S3-assets"

    # BUG-0086: CloudFront using S3 website endpoint instead of OAI — bucket must be public (CWE-668, CVSS 6.0, HIGH, Tier 2)
    # No origin_access_identity configured
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-assets"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    # BUG-0087: CloudFront allows HTTP — content served over unencrypted connection (CWE-319, CVSS 5.0, MEDIUM, Tier 2)
    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # BUG-0088: Using default CloudFront SSL certificate — no custom domain SSL (CWE-295, CVSS 4.0, MEDIUM, Tier 3)
  viewer_certificate {
    cloudfront_default_certificate = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # BUG-0089: Minimum TLS version too low — allows TLS 1.0 which is deprecated and vulnerable (CWE-326, CVSS 5.5, MEDIUM, Tier 2)
  # Default minimum_protocol_version is TLSv1 when using default certificate

  tags = {
    Name        = "brink-deployer-prod-cdn"
    Environment = "prod"
  }
}

# ─── Production Alarms ────────────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "brink-deployer-prod-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "High CPU utilization on production ECS"
  alarm_actions       = []
  # BUG-0090: Alarm has no actions configured — alerts fire but nobody is notified (CWE-778, CVSS 4.0, BEST_PRACTICE, Tier 3)

  dimensions = {
    ClusterName = "brink-deployer-prod"
    ServiceName = "brink-deployer-prod-service"
  }

  tags = {
    Environment = "prod"
  }
}

# ─── Production Outputs ──────────────────────────────────────────────────────

output "prod_vpc_id" {
  value = module.infrastructure.vpc_id
}

output "prod_ecs_cluster" {
  value = module.infrastructure.ecs_cluster_arn
}

output "prod_rds_endpoint" {
  value = module.infrastructure.rds_endpoint
}

output "prod_cdn_domain" {
  value = aws_cloudfront_distribution.prod.domain_name
}
