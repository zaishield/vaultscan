output "endpoint" {
  value = "${var.prefix}-postgres-postgresql.${var.kubernetes_namespace}.svc.cluster.local:5432"
}
output "replica_endpoint" {
  value = var.enable_replica ? "${var.prefix}-postgres-postgresql-read.${var.kubernetes_namespace}.svc.cluster.local:5432" : ""
}
output "dsn_secret_name" { value = kubernetes_secret_v1.dsn.metadata[0].name }
output "database_name"   { value = "vaultscan" }
