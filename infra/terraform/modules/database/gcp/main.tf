# GCP Cloud SQL Postgres.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google     = { source = "hashicorp/google",     version = ">= 5.30, < 6.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,  < 4.0" }
  }
}

# Database master password — rotate on token bump only.
# Mirrors the AWS module's pattern; see modules/database/aws/main.tf
# for the operator-facing rotation runbook.
resource "random_password" "db" {
  length  = 32
  special = false

  keepers = {
    rotation_token = var.db_password_rotation_token
  }
}

resource "google_sql_database_instance" "primary" {
  name             = "${var.prefix}-primary"
  database_version = var.engine_version
  region           = var.region
  project          = var.project_id

  deletion_protection = var.environment == "prod"

  settings {
    tier                  = var.tier
    availability_type     = var.environment == "prod" ? "REGIONAL" : "ZONAL"
    disk_size             = var.allocated_storage_gb
    disk_type             = "PD_SSD"
    disk_autoresize       = true
    edition               = "ENTERPRISE"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = var.environment == "prod"
      transaction_log_retention_days = var.environment == "prod" ? 7 : 1
      backup_retention_settings {
        retained_backups = var.environment == "prod" ? 30 : 7
      }
    }
    ip_configuration {
      ipv4_enabled    = false
      private_network = var.vpc_self_link
      require_ssl     = true
    }
    insights_config {
      query_insights_enabled = true
    }
    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }
  }
}

resource "google_sql_database_instance" "replica" {
  count                = var.enable_replica ? 1 : 0
  name                 = "${var.prefix}-replica"
  database_version     = var.engine_version
  region               = var.region
  project              = var.project_id
  master_instance_name = google_sql_database_instance.primary.name
  deletion_protection  = false

  settings {
    tier              = var.replica_tier
    availability_type = "ZONAL"
    disk_autoresize   = true
    edition           = "ENTERPRISE"

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.vpc_self_link
      require_ssl     = true
    }
  }
}

resource "google_sql_database" "vaultscan" {
  name     = "vaultscan"
  instance = google_sql_database_instance.primary.name
  project  = var.project_id
}

resource "google_sql_user" "vaultscan" {
  name     = "vaultscan"
  instance = google_sql_database_instance.primary.name
  password = random_password.db.result
  project  = var.project_id
}

resource "kubernetes_secret_v1" "dsn" {
  metadata {
    name      = "${var.prefix}-db"
    namespace = var.kubernetes_namespace
  }
  data = {
    VAULTSCAN_DATABASE_URL         = "postgres://vaultscan:${random_password.db.result}@${google_sql_database_instance.primary.private_ip_address}:5432/vaultscan?sslmode=require"
    VAULTSCAN_DATABASE_REPLICA_URL = var.enable_replica ? "postgres://vaultscan:${random_password.db.result}@${google_sql_database_instance.replica[0].private_ip_address}:5432/vaultscan?sslmode=require" : ""
  }
  type = "Opaque"
}
