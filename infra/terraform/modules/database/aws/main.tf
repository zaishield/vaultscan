# AWS RDS Postgres — multi-AZ in prod, single in lower envs.
# Optional read replica controlled by `enable_replica`.
#
# Returns a kubernetes Secret holding the DSN so the Helm chart can
# reference it via secrets.existingSecret.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws        = { source = "hashicorp/aws",        version = ">= 5.50, < 6.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,  < 4.0" }
  }
}

# Database master password.
#
# Rotation lifecycle: we want a rotate-on-trigger flow rather than
# regenerate-on-every-plan. Adding `keepers = { rotate = var.db_password_rotation_token }`
# makes the password resource sensitive only to that operator-
# controlled variable: bump rotation_token in tfvars to mint a new
# password; leave it alone to keep the existing one. This avoids the
# previous "every random_password apply regenerates and disconnects
# every live consumer" footgun.
#
# State loss recovery: a fresh state will rotate the password (no
# keeper match), then aws_db_instance.master_password gets set to the
# new value, and the secret in Secrets Manager is updated. Live apps
# referencing the old password via the Secrets Manager hash will
# rotate at their next pull. Document this in the runbook so ops
# doesn't think they're locked out.
resource "random_password" "db" {
  length  = 32
  special = false

  keepers = {
    rotation_token = var.db_password_rotation_token
  }
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.prefix}-db"
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "db" {
  name        = "${var.prefix}-db-sg"
  description = "Postgres access from within the cluster VPC."
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_db_parameter_group" "pg" {
  name   = "${var.prefix}-pg-params"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"   # log statements >1s
  }
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "primary" {
  identifier               = "${var.prefix}-primary"
  engine                   = "postgres"
  engine_version           = var.engine_version
  instance_class           = var.instance_class
  allocated_storage        = var.allocated_storage_gb
  storage_type             = "gp3"
  storage_encrypted        = true
  db_name                  = "vaultscan"
  username                 = "vaultscan"
  password                 = random_password.db.result
  db_subnet_group_name     = aws_db_subnet_group.this.name
  vpc_security_group_ids   = [aws_security_group.db.id]
  parameter_group_name     = aws_db_parameter_group.pg.name
  multi_az                 = var.environment == "prod"
  backup_retention_period  = var.environment == "prod" ? 30 : 7
  delete_automated_backups = false
  deletion_protection      = var.environment == "prod"
  skip_final_snapshot      = var.environment != "prod"
  final_snapshot_identifier = var.environment == "prod" ? "${var.prefix}-final" : null
  performance_insights_enabled = var.environment != "dev"
  monitoring_interval         = 60
  apply_immediately           = var.environment != "prod"
  publicly_accessible         = false
  tags                        = var.tags
}

resource "aws_db_instance" "replica" {
  count                  = var.enable_replica ? 1 : 0
  identifier             = "${var.prefix}-replica"
  replicate_source_db    = aws_db_instance.primary.identifier
  instance_class         = var.replica_instance_class
  publicly_accessible    = false
  skip_final_snapshot    = true
  performance_insights_enabled = true
  tags                   = var.tags
}

# k8s Secret that the Helm chart consumes via secrets.existingSecret.
# Contains every key the API reads from VAULTSCAN_DATABASE_URL +
# VAULTSCAN_DATABASE_REPLICA_URL.
resource "kubernetes_secret_v1" "dsn" {
  metadata {
    name      = "${var.prefix}-db"
    namespace = var.kubernetes_namespace
  }
  data = {
    VAULTSCAN_DATABASE_URL = "postgres://vaultscan:${random_password.db.result}@${aws_db_instance.primary.endpoint}/vaultscan?sslmode=require"
    VAULTSCAN_DATABASE_REPLICA_URL = var.enable_replica ? "postgres://vaultscan:${random_password.db.result}@${aws_db_instance.replica[0].endpoint}/vaultscan?sslmode=require" : ""
  }
  type = "Opaque"
}
