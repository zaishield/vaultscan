output "bucket_name"  { value = aws_s3_bucket.evidence.bucket }
output "endpoint_url" { value = "https://s3.${var.region}.amazonaws.com" }
output "access_credentials_secret_name" { value = kubernetes_secret_v1.creds.metadata[0].name }

output "secret_data" {
  sensitive = true
  value = {
    VAULTSCAN_OBJECT_STORE_URL    = "https://s3.${var.region}.amazonaws.com"
    VAULTSCAN_OBJECT_STORE_BUCKET = aws_s3_bucket.evidence.bucket
    VAULTSCAN_OBJECT_STORE_REGION = var.region
    VAULTSCAN_OBJECT_STORE_KEY    = aws_iam_access_key.api.id
    VAULTSCAN_OBJECT_STORE_SECRET = aws_iam_access_key.api.secret
  }
}
