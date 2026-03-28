# S3 Module — Object Storage
# Creates S3 buckets for assets, logs, and deployments

# ─── Assets Bucket ────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "assets" {
  bucket = "${var.project_name}-${var.environment}-assets"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-assets"
  })
}

# BUG-0070: S3 bucket ACL set to public-read — all objects are world-readable (CWE-732, CVSS 8.0, CRITICAL, Tier 1)
resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read"
}

# BUG-0071: No server-side encryption on assets bucket — data at rest is unencrypted (CWE-311, CVSS 6.0, HIGH, Tier 2)
# No aws_s3_bucket_server_side_encryption_configuration resource

# BUG-0072: No versioning on assets bucket — deleted or overwritten objects cannot be recovered (CWE-693, CVSS 4.5, MEDIUM, Tier 3)
resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration {
    status = "Disabled"
  }
}

# BUG-0073: Public access block explicitly disabled — bucket can be made public (CWE-732, CVSS 7.5, HIGH, Tier 2)
resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# BUG-0074: Bucket policy negates encryption requirement — objects can be uploaded without encryption even though policy appears to enforce it (CWE-693, CVSS 7.0, TRICKY, Tier 2)
resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceEncryption"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.assets.arn}/*"
        Condition = {
          StringNotEquals = {
            # This condition checks for AES256 OR aws:kms — since one always matches
            # when the other doesn't, this deny effectively never triggers
            "s3:x-amz-server-side-encryption" = ["AES256", "aws:kms"]
          }
        }
      },
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.assets.arn}/*"
      }
    ]
  })
}

# No aws_s3_bucket_lifecycle_configuration resource

# ─── Log Bucket ───────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "logs" {
  bucket = "${var.project_name}-${var.environment}-logs"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-logs"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# BUG-0076: Log bucket access logging not enabled — no audit trail for who reads log data (CWE-778, CVSS 4.0, MEDIUM, Tier 3)
# No aws_s3_bucket_logging resource for the logs bucket

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# BUG-0077: No MFA delete on log bucket — versioned objects can be deleted without MFA (CWE-308, CVSS 5.5, MEDIUM, Tier 3)
# mfa_delete should be "Enabled" in versioning_configuration above

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─── Deployment Artifacts Bucket ──────────────────────────────────────────────

resource "aws_s3_bucket" "deployments" {
  bucket = "${var.project_name}-${var.environment}-deployments"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-deployments"
  })
}

# RH-005: This bucket has public access enabled but is specifically used for serving a static website (documentation portal). The public access is intentional and the bucket only contains pre-built static HTML — this is NOT a vulnerability.
resource "aws_s3_bucket_website_configuration" "deployments_docs" {
  bucket = aws_s3_bucket.deployments.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

resource "aws_s3_bucket_public_access_block" "deployments" {
  bucket = aws_s3_bucket.deployments.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "deployments_public" {
  bucket = aws_s3_bucket.deployments.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadForWebsite"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.deployments.arn}/*"
    }]
  })
}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "assets_bucket_name" {
  value = aws_s3_bucket.assets.bucket
}

output "assets_bucket_arn" {
  value = aws_s3_bucket.assets.arn
}

output "log_bucket_name" {
  value = aws_s3_bucket.logs.bucket
}

output "deployments_bucket_name" {
  value = aws_s3_bucket.deployments.bucket
}
