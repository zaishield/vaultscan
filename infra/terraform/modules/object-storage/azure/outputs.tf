output "bucket_name"  { value = azurerm_storage_container.evidence.name }
output "endpoint_url" { value = azurerm_storage_account.evidence.primary_blob_endpoint }
output "access_credentials_secret_name" { value = kubernetes_secret_v1.creds.metadata[0].name }

output "secret_data" {
  sensitive = true
  value = {
    VAULTSCAN_OBJECT_STORE_URL    = azurerm_storage_account.evidence.primary_blob_endpoint
    VAULTSCAN_OBJECT_STORE_BUCKET = azurerm_storage_container.evidence.name
    VAULTSCAN_OBJECT_STORE_REGION = var.location
    VAULTSCAN_OBJECT_STORE_KEY    = azurerm_storage_account.evidence.name
    VAULTSCAN_OBJECT_STORE_SECRET = azurerm_storage_account.evidence.primary_access_key
  }
}
