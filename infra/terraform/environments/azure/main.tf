provider "azurerm" {
  features {}
}

provider "kubernetes" {
  host                   = module.kubernetes.cluster_endpoint
  cluster_ca_certificate = base64decode(module.kubernetes.cluster_ca)
  # AKS kubeconfig is admin-credentials-based in the basic flow; for
  # production, switch to azurerm_kubernetes_cluster_user_credentials
  # + AAD exec plugin.
}

provider "helm" {
  kubernetes {
    host                   = module.kubernetes.cluster_endpoint
    cluster_ca_certificate = base64decode(module.kubernetes.cluster_ca)
  }
}

locals {
  full_prefix = "${var.prefix}-${var.environment}"
}

module "kubernetes" {
  source             = "../../modules/kubernetes/azure"
  prefix             = local.full_prefix
  environment        = var.environment
  location           = var.location
  availability_zones = var.availability_zones
  kubernetes_version = var.kubernetes_version
  node_vm_size       = var.node_vm_size
  node_min_size      = var.node_min_size
  node_max_size      = var.node_max_size
  node_desired_size  = var.node_desired_size
}

module "database" {
  source              = "../../modules/database/azure"
  prefix              = local.full_prefix
  environment         = var.environment
  resource_group_name = module.kubernetes.resource_group_name
  location            = var.location
  sku_name            = var.db_sku_name
  storage_mb          = var.db_storage_mb
  enable_replica      = var.enable_db_replica

  depends_on = [module.kubernetes]
}

module "object_storage" {
  source              = "../../modules/object-storage/azure"
  bucket_prefix       = local.full_prefix
  environment         = var.environment
  resource_group_name = module.kubernetes.resource_group_name
  location            = var.location
}

module "opensearch" {
  source            = "../../modules/opensearch/generic"
  cluster_name      = "${local.full_prefix}-os"
  environment       = var.environment
  cluster_namespace = "vaultscan"

  depends_on = [module.kubernetes]
}

module "vaultscan" {
  source        = "../../modules/vaultscan"
  release_name  = "vaultscan"
  namespace     = "vaultscan"
  environment   = var.environment
  region        = var.location
  api_public_url = var.api_public_url

  database_dsn_secret_name             = module.database.dsn_secret_name
  object_store_credentials_secret_name = module.object_storage.access_credentials_secret_name
  object_store_bucket                  = module.object_storage.bucket_name
  opensearch_endpoint                  = module.opensearch.endpoint

  depends_on = [module.database, module.object_storage, module.opensearch]
}
