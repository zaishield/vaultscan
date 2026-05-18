provider "google" {
  project = var.project_id
  region  = var.region
}

provider "kubernetes" {
  host                   = module.kubernetes.cluster_endpoint
  cluster_ca_certificate = base64decode(module.kubernetes.cluster_ca)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "gke-gcloud-auth-plugin"
  }
}

provider "helm" {
  kubernetes {
    host                   = module.kubernetes.cluster_endpoint
    cluster_ca_certificate = base64decode(module.kubernetes.cluster_ca)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "gke-gcloud-auth-plugin"
    }
  }
}

locals {
  full_prefix = "${var.prefix}-${var.environment}"
}

module "kubernetes" {
  source             = "../../modules/kubernetes/gcp"
  prefix             = local.full_prefix
  environment        = var.environment
  project_id         = var.project_id
  region             = var.region
  zones              = var.zones
  kubernetes_version = var.kubernetes_version
  node_machine_type  = var.node_machine_type
  node_min_size      = var.node_min_size
  node_max_size      = var.node_max_size
  node_desired_size  = var.node_desired_size
}

module "database" {
  source           = "../../modules/database/gcp"
  prefix           = local.full_prefix
  environment      = var.environment
  project_id       = var.project_id
  region           = var.region
  tier             = var.db_tier
  allocated_storage_gb = var.db_storage_gb
  vpc_self_link    = module.kubernetes.vpc_id
  enable_replica   = var.enable_db_replica

  depends_on = [module.kubernetes]
}

module "object_storage" {
  source        = "../../modules/object-storage/gcp"
  bucket_prefix = local.full_prefix
  environment   = var.environment
  project_id    = var.project_id
  location      = upper(substr(var.region, 0, 2))   # "EU" / "US"
}

# GCP delegates to the OpenSearch operator (no first-party managed
# OpenSearch). Same module the generic flavor uses.
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
  region        = var.region
  api_public_url = var.api_public_url

  database_dsn_secret_name             = module.database.dsn_secret_name
  object_store_credentials_secret_name = module.object_storage.access_credentials_secret_name
  object_store_bucket                  = module.object_storage.bucket_name
  opensearch_endpoint                  = module.opensearch.endpoint

  depends_on = [module.database, module.object_storage, module.opensearch]
}
