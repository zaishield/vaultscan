output "bucket_name"  { value = google_storage_bucket.evidence.name }
output "endpoint_url" { value = "https://storage.googleapis.com" }
output "access_credentials_secret_name" { value = kubernetes_secret_v1.creds.metadata[0].name }

output "secret_data" {
  sensitive = true
  value = {
    VAULTSCAN_OBJECT_STORE_URL    = "https://storage.googleapis.com"
    VAULTSCAN_OBJECT_STORE_BUCKET = google_storage_bucket.evidence.name
    VAULTSCAN_OBJECT_STORE_REGION = var.location
    VAULTSCAN_OBJECT_STORE_KEY    = google_service_account.api.email
    VAULTSCAN_OBJECT_STORE_SECRET = google_service_account_key.api.private_key
  }
}
