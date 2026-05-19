# Azure Database for PostgreSQL — Flexible Server.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm    = { source = "hashicorp/azurerm",    version = ">= 3.100, < 4.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29,  < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,   < 4.0" }
  }
}

# Database master password — rotate on token bump only.
# Mirrors the AWS + GCP modules' pattern; see
# modules/database/aws/main.tf for the operator-facing rotation
# runbook.
resource "random_password" "db" {
  length  = 32
  special = false

  keepers = {
    rotation_token = var.db_password_rotation_token
  }
}

resource "azurerm_postgresql_flexible_server" "primary" {
  name                          = "${var.prefix}-primary"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  version                       = var.engine_version
  sku_name                      = var.sku_name
  storage_mb                    = var.storage_mb
  delegated_subnet_id           = var.delegated_subnet_id
  private_dns_zone_id           = var.private_dns_zone_id
  zone                          = var.zone
  administrator_login           = "vaultscan"
  administrator_password        = random_password.db.result
  public_network_access_enabled = false
  backup_retention_days         = var.environment == "prod" ? 30 : 7
  geo_redundant_backup_enabled  = var.environment == "prod"

  high_availability {
    mode = var.environment == "prod" ? "ZoneRedundant" : "Disabled"
  }

  tags = var.tags
}

resource "azurerm_postgresql_flexible_server_database" "vaultscan" {
  name      = "vaultscan"
  server_id = azurerm_postgresql_flexible_server.primary.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server" "replica" {
  count                         = var.enable_replica ? 1 : 0
  name                          = "${var.prefix}-replica"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  create_mode                   = "Replica"
  source_server_id              = azurerm_postgresql_flexible_server.primary.id
  delegated_subnet_id           = var.delegated_subnet_id
  private_dns_zone_id           = var.private_dns_zone_id
  public_network_access_enabled = false
  tags                          = var.tags
}

resource "kubernetes_secret_v1" "dsn" {
  metadata {
    name      = "${var.prefix}-db"
    namespace = var.kubernetes_namespace
  }
  data = {
    VAULTSCAN_DATABASE_URL = "postgres://vaultscan:${random_password.db.result}@${azurerm_postgresql_flexible_server.primary.fqdn}:5432/vaultscan?sslmode=require"
    VAULTSCAN_DATABASE_REPLICA_URL = var.enable_replica ? "postgres://vaultscan:${random_password.db.result}@${azurerm_postgresql_flexible_server.replica[0].fqdn}:5432/vaultscan?sslmode=require" : ""
  }
  type = "Opaque"
}
