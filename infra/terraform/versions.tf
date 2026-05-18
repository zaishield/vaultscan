# Shared version pins. Each environment composition copies the
# required-providers block it actually needs into its own
# versions.tf — Terraform requires the block to live next to the
# resources, so we can't simply `include` this file. Treat this as
# the canonical reference.

terraform {
  required_version = ">= 1.5, < 2.0"   # OpenTofu 1.6+, Terraform 1.5+

  required_providers {
    aws        = { source = "hashicorp/aws",        version = ">= 5.50, < 6.0" }
    google     = { source = "hashicorp/google",     version = ">= 5.30, < 6.0" }
    azurerm    = { source = "hashicorp/azurerm",    version = ">= 3.100, < 4.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
    helm       = { source = "hashicorp/helm",       version = ">= 2.13, < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6, < 4.0" }
    tls        = { source = "hashicorp/tls",        version = ">= 4.0, < 5.0" }
  }
}
