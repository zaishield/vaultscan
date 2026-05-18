output "endpoint"         { value = azurerm_postgresql_flexible_server.primary.fqdn }
output "replica_endpoint" { value = var.enable_replica ? azurerm_postgresql_flexible_server.replica[0].fqdn : "" }
output "dsn_secret_name"  { value = kubernetes_secret_v1.dsn.metadata[0].name }
output "database_name"    { value = azurerm_postgresql_flexible_server_database.vaultscan.name }
