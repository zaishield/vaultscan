output "bucket_name"  { value = "vaultscan-evidence" }
output "endpoint_url" { value = "http://${var.bucket_prefix}-minio.${var.kubernetes_namespace}.svc.cluster.local:9000" }
output "access_credentials_secret_name" { value = kubernetes_secret_v1.creds.metadata[0].name }
