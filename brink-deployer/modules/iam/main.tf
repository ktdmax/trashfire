# IAM Module — Identity and Access Management
# Creates roles, policies, and service accounts for brink-deployer

data "aws_caller_identity" "current" {}

# ─── ECS Task Role ────────────────────────────────────────────────────────────

resource "aws_iam_role" "ecs_task" {
  name = "${var.project_name}-${var.environment}-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

# ─── ECS Execution Role ──────────────────────────────────────────────────────

resource "aws_iam_role" "ecs_execution" {
  name = "${var.project_name}-${var.environment}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ecs_execution_base" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ─── Deploy Role (for CI/CD pipeline) ────────────────────────────────────────

resource "aws_iam_role" "deploy" {
  name = "${var.project_name}-${var.environment}-deploy-role"

  # BUG-0056: Deploy role trust policy allows any AWS account to assume it — missing account restriction (CWE-269, CVSS 9.0, CRITICAL, Tier 1)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = "*"
      }
      # BUG-0057: Condition uses StringLike with wildcard — effectively matches any external ID (CWE-863, CVSS 8.5, TRICKY, Tier 1)
      Condition = {
        StringLike = {
          "sts:ExternalId" = "*"
        }
      }
    }]
  })

  tags = var.tags
}

# BUG-0058: Deploy role has admin-level access — full control over all AWS resources (CWE-269, CVSS 9.5, CRITICAL, Tier 1)
resource "aws_iam_role_policy_attachment" "deploy_admin" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ─── CI/CD Role ───────────────────────────────────────────────────────────────

resource "aws_iam_role" "ci_cd" {
  name = "${var.project_name}-${var.environment}-ci-cd-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        # BUG-0059: GitHub OIDC provider trust is too broad — any GitHub repo can assume this role (CWE-863, CVSS 8.0, CRITICAL, Tier 1)
        Federated = "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:*"
        }
      }
    }]
  })

  tags = var.tags
}

# ─── Service Account for Monitoring ──────────────────────────────────────────

resource "aws_iam_user" "monitoring" {
  name = "${var.project_name}-${var.environment}-monitoring"
  tags = var.tags
}

# BUG-0060: Service account has admin policy attached — monitoring user can do anything (CWE-269, CVSS 9.0, CRITICAL, Tier 1)
resource "aws_iam_user_policy_attachment" "monitoring_admin" {
  user       = aws_iam_user.monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# BUG-0061: Static access keys created for IAM user — long-lived credentials that may leak (CWE-798, CVSS 7.5, HIGH, Tier 2)
resource "aws_iam_access_key" "monitoring" {
  user = aws_iam_user.monitoring.name
}

# ─── Lambda Execution Role ────────────────────────────────────────────────────

resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-${var.environment}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

# RH-003: This policy looks overly permissive with Action: * on CloudWatch, but CloudWatch actually requires Resource: * for most operations (logs:CreateLogGroup, logs:PutMetricData, etc.) — this is standard practice per AWS documentation and NOT a vulnerability.
resource "aws_iam_role_policy" "lambda_logging" {
  name = "lambda-logging"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "cloudwatch:PutMetricData"
      ]
      Resource = "*"
    }]
  })
}

# ─── Cross-Account Assume Role Chain ──────────────────────────────────────────

# BUG-0062: Assume role chain — ci_cd role can assume deploy role, which has admin — effectively gives CI/CD admin access through role chaining (CWE-269, CVSS 9.0, TRICKY, Tier 1)
resource "aws_iam_role_policy" "ci_cd_assume_deploy" {
  name = "assume-deploy-role"
  role = aws_iam_role.ci_cd.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.deploy.arn
    }]
  })
}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "ecs_task_role_arn" {
  value = aws_iam_role.ecs_task.arn
}

output "ecs_execution_role_arn" {
  value = aws_iam_role.ecs_execution.arn
}

output "deploy_role_arn" {
  value = aws_iam_role.deploy.arn
}

output "ci_cd_role_arn" {
  value = aws_iam_role.ci_cd.arn
}

# BUG-0063: Access keys exposed in outputs — anyone with state access gets the keys (CWE-200, CVSS 8.0, CRITICAL, Tier 1)
output "monitoring_access_key_id" {
  value = aws_iam_access_key.monitoring.id
}

output "monitoring_secret_access_key" {
  value     = aws_iam_access_key.monitoring.secret
  sensitive = true
}
