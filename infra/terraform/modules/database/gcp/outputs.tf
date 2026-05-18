output "endpoint"         { value = "${google_sql_database_instance.primary.private_ip_address}:5432" }
output "replica_endpoint" { value = var.enable_replica ? "${google_sql_database_instance.replica[0].private_ip_address}:5432" : "" }
output "dsn_secret_name"  { value = kubernetes_secret_v1.dsn.metadata[0].name }
output "database_name"    { value = google_sql_database.vaultscan.name }
