output "endpoint" { value = aws_db_instance.primary.endpoint }
output "replica_endpoint" {
  value = var.enable_replica ? aws_db_instance.replica[0].endpoint : ""
}
output "dsn_secret_name" { value = kubernetes_secret_v1.dsn.metadata[0].name }
output "database_name"   { value = aws_db_instance.primary.db_name }
