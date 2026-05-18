output "bucket_name"  { value = google_storage_bucket.evidence.name }
output "endpoint_url" { value = "https://storage.googleapis.com" }
output "access_credentials_secret_name" { value = kubernetes_secret_v1.creds.metadata[0].name }
