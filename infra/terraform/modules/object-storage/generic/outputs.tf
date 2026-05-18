output "bucket_name"  { value = "vaultscan-evidence" }
output "endpoint_url" { value = "http://${var.bucket_prefix}-minio.${var.kubernetes_namespace}.svc.cluster.local:9000" }
output "access_credentials_secret_name" { value = kubernetes_secret_v1.creds.metadata[0].name }

output "secret_data" {
  sensitive = true
  value = {
    VAULTSCAN_OBJECT_STORE_URL    = "http://${var.bucket_prefix}-minio.${var.kubernetes_namespace}.svc.cluster.local:9000"
    VAULTSCAN_OBJECT_STORE_BUCKET = "vaultscan-evidence"
    VAULTSCAN_OBJECT_STORE_REGION = "us-east-1"
    VAULTSCAN_OBJECT_STORE_KEY    = "vaultscan"
    VAULTSCAN_OBJECT_STORE_SECRET = random_password.secret.result
  }
}
