output "bucket_name"  { value = azurerm_storage_container.evidence.name }
output "endpoint_url" { value = azurerm_storage_account.evidence.primary_blob_endpoint }
output "access_credentials_secret_name" { value = kubernetes_secret_v1.creds.metadata[0].name }
