output "bucket_name"  { value = aws_s3_bucket.evidence.bucket }
output "endpoint_url" { value = "https://s3.${var.region}.amazonaws.com" }
output "access_credentials_secret_name" { value = kubernetes_secret_v1.creds.metadata[0].name }
