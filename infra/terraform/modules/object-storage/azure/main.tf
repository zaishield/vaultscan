# Azure Blob Storage + container + access keys.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm    = { source = "hashicorp/azurerm",    version = ">= 3.100, < 4.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29,  < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,   < 4.0" }
  }
}

resource "random_id" "suffix" {
  byte_length = 3
}

resource "azurerm_storage_account" "evidence" {
  # Storage account names must be 3-24 lower-case alphanum, globally unique.
  name                            = lower(replace("${var.bucket_prefix}${random_id.suffix.hex}", "-", ""))
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = var.environment == "prod" ? "GZRS" : "LRS"
  min_tls_version                 = "TLS1_2"
  public_network_access_enabled   = false
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = true

  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 30 }
    container_delete_retention_policy { days = 30 }
  }

  tags = var.tags
}

resource "azurerm_storage_container" "evidence" {
  name                  = "evidence"
  storage_account_name  = azurerm_storage_account.evidence.name
  container_access_type = "private"
}

resource "kubernetes_secret_v1" "creds" {
  metadata {
    name      = "${var.bucket_prefix}-object-store"
    namespace = var.kubernetes_namespace
  }
  data = {
    VAULTSCAN_OBJECT_STORE_URL    = azurerm_storage_account.evidence.primary_blob_endpoint
    VAULTSCAN_OBJECT_STORE_BUCKET = azurerm_storage_container.evidence.name
    VAULTSCAN_OBJECT_STORE_REGION = var.location
    VAULTSCAN_OBJECT_STORE_KEY    = azurerm_storage_account.evidence.name
    VAULTSCAN_OBJECT_STORE_SECRET = azurerm_storage_account.evidence.primary_access_key
  }
  type = "Opaque"
}
