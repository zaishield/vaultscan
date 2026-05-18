output "endpoint"         { value = azurerm_postgresql_flexible_server.primary.fqdn }
output "replica_endpoint" { value = var.enable_replica ? azurerm_postgresql_flexible_server.replica[0].fqdn : "" }
output "dsn_secret_name"  { value = kubernetes_secret_v1.dsn.metadata[0].name }
output "database_name"    { value = azurerm_postgresql_flexible_server_database.vaultscan.name }

output "secret_data" {
  sensitive = true
  value = {
    VAULTSCAN_DATABASE_URL         = "postgres://vaultscan:${random_password.db.result}@${azurerm_postgresql_flexible_server.primary.fqdn}:5432/vaultscan?sslmode=require"
    VAULTSCAN_DATABASE_REPLICA_URL = var.enable_replica ? "postgres://vaultscan:${random_password.db.result}@${azurerm_postgresql_flexible_server.replica[0].fqdn}:5432/vaultscan?sslmode=require" : ""
  }
}
