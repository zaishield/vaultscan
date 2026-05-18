terraform {
  backend "azurerm" {
    resource_group_name  = "vaultscan-tfstate-rg"   # CHANGE ME
    storage_account_name = "vaultscantfstate"        # CHANGE ME (globally unique)
    container_name       = "tfstate"
    key                  = "vaultscan/azure/terraform.tfstate"
  }
}
