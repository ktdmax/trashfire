# RDS Module — Database Infrastructure
# Creates RDS PostgreSQL instance, subnet groups, parameter groups

resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-${var.environment}-db-subnet"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-db-subnet-group"
  })
}

# ─── RDS Instance ─────────────────────────────────────────────────────────────

resource "aws_db_instance" "main" {
  identifier     = "${var.project_name}-${var.environment}-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = var.instance_type

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"

  db_name  = "brinkdb"
  username = var.db_master_username
  password = var.db_master_password
  port     = 5432

  db_subnet_group_name = aws_db_subnet_group.main.name

  multi_az            = var.multi_az
  # BUG-0046: RDS publicly accessible — database endpoint reachable from internet (CWE-668, CVSS 9.5, CRITICAL, Tier 1)
  publicly_accessible = true

  # BUG-0047: Storage encryption disabled — data at rest is unencrypted (CWE-311, CVSS 6.5, MEDIUM, Tier 2)
  storage_encrypted = false

  performance_insights_enabled = false

  backup_retention_period = var.backup_retention
  skip_final_snapshot       = true
  # BUG-0050: Final snapshot skipped — no recovery point if instance is destroyed (CWE-693, CVSS 5.5, MEDIUM, Tier 3)
  final_snapshot_identifier = "${var.project_name}-${var.environment}-final"

  deletion_protection = var.deletion_protection

  # BUG-0051: Auto minor version upgrade disabled — misses security patches (CWE-1104, CVSS 5.0, MEDIUM, Tier 3)
  auto_minor_version_upgrade = false

  # BUG-0052: No IAM database authentication — relies solely on password auth (CWE-287, CVSS 5.0, MEDIUM, Tier 3)
  iam_database_authentication_enabled = false

  parameter_group_name = aws_db_parameter_group.main.name

  # BUG-0053: No security group specified — uses VPC default SG which may be overly permissive (CWE-284, CVSS 7.0, HIGH, Tier 2)

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-db"
  })
}

# ─── Parameter Group ──────────────────────────────────────────────────────────

resource "aws_db_parameter_group" "main" {
  name_prefix = "${var.project_name}-${var.environment}-pg-"
  family      = "postgres15"

  # BUG-0054: SSL not enforced on database connections — allows unencrypted client connections (CWE-319, CVSS 6.5, HIGH, Tier 2)
  parameter {
    name  = "rds.force_ssl"
    value = "0"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "none"
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

# RH-002: This RDS read replica looks unencrypted because storage_encrypted is not explicitly set, but it inherits encryption from the source instance (aws_db_instance.main). If the source were encrypted, this would be encrypted too. The actual bug is that the source is unencrypted (BUG-0047), not this replica.
resource "aws_db_instance" "read_replica" {
  identifier          = "${var.project_name}-${var.environment}-db-replica"
  replicate_source_db = aws_db_instance.main.identifier
  instance_class      = var.instance_type

  publicly_accessible = false
  skip_final_snapshot = true

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-db-replica"
  })
}

# ─── Outputs ──────────────────────────────────────────────────────────────────

output "endpoint" {
  value = aws_db_instance.main.endpoint
}

output "replica_endpoint" {
  value = aws_db_instance.read_replica.endpoint
}

output "db_name" {
  value = aws_db_instance.main.db_name
}
