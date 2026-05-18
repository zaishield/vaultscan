provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kubeconfig_context != "" ? var.kubeconfig_context : null
}

provider "helm" {
  kubernetes {
    config_path    = var.kubeconfig_path
    config_context = var.kubeconfig_context != "" ? var.kubeconfig_context : null
  }
}

locals {
  full_prefix = "${var.prefix}-${var.environment}"
}

module "kubernetes" {
  source          = "../../modules/kubernetes/generic"
  prefix          = local.full_prefix
  environment     = var.environment
  kubeconfig_path = var.kubeconfig_path
  cluster_name    = var.cluster_name
}

module "database" {
  source         = "../../modules/database/generic"
  prefix         = local.full_prefix
  environment    = var.environment
  storage_gb     = var.db_storage_gb
  enable_replica = var.enable_db_replica
}

module "object_storage" {
  source        = "../../modules/object-storage/generic"
  bucket_prefix = local.full_prefix
  environment   = var.environment
  storage_gb    = var.object_store_gb
}

module "opensearch" {
  source            = "../../modules/opensearch/generic"
  cluster_name      = "${local.full_prefix}-os"
  environment       = var.environment
  cluster_namespace = "vaultscan"
}

module "vaultscan" {
  source        = "../../modules/vaultscan"
  release_name  = "vaultscan"
  namespace     = "vaultscan"
  environment   = var.environment
  region        = var.region
  api_public_url = var.api_public_url

  database_dsn_secret_name             = module.database.dsn_secret_name
  object_store_credentials_secret_name = module.object_storage.access_credentials_secret_name
  object_store_bucket                  = module.object_storage.bucket_name
  opensearch_endpoint                  = module.opensearch.endpoint
  database_secret_data                 = module.database.secret_data
  object_store_secret_data             = module.object_storage.secret_data

  # When running against a local kind cluster, layer the
  # local-overrides.yaml on top to disable Ingress / LoadBalancer /
  # Kyverno / backup. Toggle in <env>.tfvars.
  extra_values_files = var.local_overrides_enabled ? ["${path.module}/local-overrides.yaml"] : []

  depends_on = [module.database, module.object_storage, module.opensearch]
}
