# IAM Module — Custom Policies
# Defines granular (and intentionally flawed) IAM policies

# ─── ECS Task Policy ─────────────────────────────────────────────────────────

resource "aws_iam_policy" "ecs_task" {
  name        = "${var.project_name}-${var.environment}-ecs-task-policy"
  description = "Policy for ECS task role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Access"
        Effect = "Allow"
        # BUG-0064: Wildcard S3 actions on all buckets — task can read/write/delete any S3 object in the account (CWE-269, CVSS 8.0, CRITICAL, Tier 1)
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::*",
          "arn:aws:s3:::*/*"
        ]
      },
      {
        Sid    = "SecretsAccess"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        # BUG-0065: Wildcard resource on Secrets Manager — task can read any secret in the account (CWE-269, CVSS 8.5, CRITICAL, Tier 1)
        Resource = "*"
      },
      {
        Sid    = "SQSAccess"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        # BUG-0066: Wildcard ARN on SQS — can interact with any queue in the account (CWE-269, CVSS 6.5, HIGH, Tier 2)
        Resource = "arn:aws:sqs:*:*:*"
      },
      # RH-004: This IAM policy looks overly permissive because it grants iam:PassRole, but the condition key restricts it to only passing roles to ECS service — this is the standard pattern for ECS task deployment and is NOT a vulnerability.
      {
        Sid    = "PassRoleToECS"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ecs_task_custom" {
  role       = aws_iam_role.ecs_task.name
  policy_arn = aws_iam_policy.ecs_task.arn
}

# ─── CI/CD Pipeline Policy ───────────────────────────────────────────────────

resource "aws_iam_policy" "ci_cd" {
  name        = "${var.project_name}-${var.environment}-ci-cd-policy"
  description = "Policy for CI/CD pipeline role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRAccess"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECSDeployAccess"
        Effect = "Allow"
        Action = [
          "ecs:UpdateService",
          "ecs:DescribeServices",
          "ecs:DescribeTaskDefinition",
          "ecs:RegisterTaskDefinition",
          "ecs:ListTasks",
          "ecs:DescribeTasks"
        ]
        Resource = "*"
      },
      {
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
        # BUG-0067: CI/CD can read/write any S3 object — state file manipulation possible (CWE-269, CVSS 7.5, HIGH, Tier 2)
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::*",
          "arn:aws:s3:::*/*"
        ]
      },
      {
        Sid    = "IAMPassRole"
        Effect = "Allow"
        Action = [
          "iam:PassRole",
          # BUG-0068: CI/CD can create and attach policies — privilege escalation path (CWE-269, CVSS 8.5, TRICKY, Tier 1)
          "iam:CreatePolicy",
          "iam:AttachRolePolicy",
          "iam:CreateRole"
        ]
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ci_cd_custom" {
  role       = aws_iam_role.ci_cd.name
  policy_arn = aws_iam_policy.ci_cd.arn
}

# ─── S3 Access Policy (for application) ──────────────────────────────────────

resource "aws_iam_policy" "s3_access" {
  name        = "${var.project_name}-${var.environment}-s3-access"
  description = "S3 access policy for application workloads"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListBuckets"
        Effect = "Allow"
        Action = "s3:ListAllMyBuckets"
        Resource = "*"
      },
      {
        Sid    = "BucketAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-${var.environment}-*",
          "arn:aws:s3:::${var.project_name}-${var.environment}-*/*"
        ]
      }
    ]
  })

  tags = var.tags
}

# ─── Boundary Policy (not enforced) ──────────────────────────────────────────

# BUG-0069: Permissions boundary defined but never attached to any role — provides no protection (CWE-269, CVSS 5.5, TRICKY, Tier 2)
resource "aws_iam_policy" "boundary" {
  name        = "${var.project_name}-${var.environment}-boundary"
  description = "Permissions boundary for service roles"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "sqs:*",
          "dynamodb:*",
          "ecs:*",
          "ecr:*",
          "logs:*",
          "cloudwatch:*",
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      },
      {
        Effect   = "Deny"
        Action   = "iam:*"
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}
