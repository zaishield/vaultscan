output "endpoint" { value = aws_db_instance.primary.endpoint }
output "replica_endpoint" {
  value = var.enable_replica ? aws_db_instance.replica[0].endpoint : ""
}
output "dsn_secret_name" { value = kubernetes_secret_v1.dsn.metadata[0].name }
output "database_name"   { value = aws_db_instance.primary.db_name }

# Raw secret data — consumed by the vaultscan module to build its
# consolidated Secret without a data-source chain.
output "secret_data" {
  sensitive = true
  value = {
    VAULTSCAN_DATABASE_URL         = "postgres://vaultscan:${random_password.db.result}@${aws_db_instance.primary.endpoint}/vaultscan?sslmode=require"
    VAULTSCAN_DATABASE_REPLICA_URL = var.enable_replica ? "postgres://vaultscan:${random_password.db.result}@${aws_db_instance.replica[0].endpoint}/vaultscan?sslmode=require" : ""
  }
}
