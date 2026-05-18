terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    azurerm    = { source = "hashicorp/azurerm",    version = ">= 3.100, < 4.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29,  < 3.0" }
    helm       = { source = "hashicorp/helm",       version = ">= 2.13,  < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,   < 4.0" }
  }
}
