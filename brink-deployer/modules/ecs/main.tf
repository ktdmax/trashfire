# ECS Module — Container Orchestration
# Creates ECS cluster, task definitions, services, and ALB

resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-${var.environment}"

  # BUG-0033: Container Insights disabled — no container-level monitoring or anomaly detection (CWE-778, CVSS 4.0, MEDIUM, Tier 3)
  # setting {
  #   name  = "containerInsights"
  #   value = "enabled"
  # }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-cluster"
  })
}

# ─── Task Definition ──────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-${var.environment}-app"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "app"
      image = var.container_image
      # BUG-0034: Container runs as root — container escape gains host root access (CWE-250, CVSS 7.5, HIGH, Tier 2)
      # No user field specified — defaults to root

      portMappings = [
        {
          containerPort = var.container_port
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "NODE_ENV"
          value = var.environment
        },
        # BUG-0035: Database credentials passed as plaintext environment variables — visible in task definition, console, and API (CWE-312, CVSS 8.0, CRITICAL, Tier 1)
        {
          name  = "DB_HOST"
          value = "brink-db.cluster-xxxx.us-east-1.rds.amazonaws.com"
        },
        {
          name  = "DB_PASSWORD"
          value = "Br1nk_D3pl0y3r_2024!"
        },
        {
          name  = "DB_USER"
          value = "brinkadmin"
        },
        # BUG-0036: API key hardcoded in container environment (CWE-798, CVSS 8.5, CRITICAL, Tier 1)
        {
          name  = "STRIPE_SECRET_KEY"
          value = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/${var.project_name}-${var.environment}"
          "awslogs-region"        = "us-east-1"
          "awslogs-stream-prefix" = "app"
        }
      }

      # BUG-0037: readonlyRootFilesystem not set — container filesystem is writable, allows malware persistence (CWE-732, CVSS 5.5, HIGH, Tier 2)
      # healthCheck not configured — unhealthy containers keep serving traffic
    }
  ])

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-task"
  })
}

# ─── ECS Service ──────────────────────────────────────────────────────────────

resource "aws_ecs_service" "app" {
  name            = "${var.project_name}-${var.environment}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    # BUG-0038: ECS tasks assigned public IPs — containers directly internet-routable (CWE-668, CVSS 7.0, HIGH, Tier 2)
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = var.container_port
  }

  # BUG-0039: No deployment circuit breaker — bad deployments keep rolling out (CWE-693, CVSS 4.0, MEDIUM, Tier 3)

  tags = var.tags
}

# ─── Application Load Balancer ────────────────────────────────────────────────

resource "aws_lb" "app" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ecs_tasks.id]
  subnets            = var.subnet_ids

  # BUG-0040: ALB access logging disabled — no request-level audit trail (CWE-778, CVSS 5.0, MEDIUM, Tier 3)
  # access_logs {
  #   bucket  = "brink-deployer-alb-logs"
  #   enabled = true
  # }

  # BUG-0041: Drop invalid headers disabled — HTTP request smuggling possible (CWE-444, CVSS 6.5, HIGH, Tier 2)
  drop_invalid_header_fields = false

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb"
  })
}

# BUG-0042: HTTP listener without redirect to HTTPS — traffic sent in plaintext (CWE-319, CVSS 5.5, MEDIUM, Tier 2)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_target_group" "app" {
  name        = "${var.project_name}-${var.environment}-tg"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = var.health_check_path
    port                = "traffic-port"
    timeout             = 5
    unhealthy_threshold = 3
  }

  tags = var.tags
}

# ─── ECS Security Group ──────────────────────────────────────────────────────

resource "aws_security_group" "ecs_tasks" {
  name_prefix = "${var.project_name}-${var.environment}-ecs-"
  vpc_id      = var.vpc_id

  # BUG-0043: ECS security group allows all inbound traffic — no port restriction (CWE-284, CVSS 7.5, HIGH, Tier 2)
  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ecs-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ─── IAM Roles for ECS ───────────────────────────────────────────────────────

resource "aws_iam_role" "ecs_execution" {
  name = "${var.project_name}-${var.environment}-ecs-execution"

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

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "ecs_task" {
  name = "${var.project_name}-${var.environment}-ecs-task"

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

# BUG-0044: ECS task role has overly permissive S3 and SQS access — violates least privilege (CWE-269, CVSS 7.0, HIGH, Tier 2)
resource "aws_iam_role_policy" "ecs_task" {
  name = "ecs-task-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "sqs:*",
          "dynamodb:*",
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

# ─── Auto Scaling ─────────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = 10
  min_capacity       = var.desired_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.app.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "cluster_arn" {
  value = aws_ecs_cluster.main.arn
}

output "service_url" {
  value = "http://${aws_lb.app.dns_name}"
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.app.arn
}
