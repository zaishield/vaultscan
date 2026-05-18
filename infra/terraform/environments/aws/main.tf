# AWS environment composition. The same shape exists under gcp/,
# azure/, and generic/ — only the module sources differ.

provider "aws" {
  region = var.region
}

provider "kubernetes" {
  host                   = module.kubernetes.cluster_endpoint
  cluster_ca_certificate = base64decode(module.kubernetes.cluster_ca)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.kubernetes.cluster_name, "--region", var.region]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.kubernetes.cluster_endpoint
    cluster_ca_certificate = base64decode(module.kubernetes.cluster_ca)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.kubernetes.cluster_name, "--region", var.region]
    }
  }
}

locals {
  full_prefix = "${var.prefix}-${var.environment}"
  tags = {
    "vaultscan.io/environment" = var.environment
    "vaultscan.io/managed-by"  = "terraform"
  }
}

module "kubernetes" {
  source             = "../../modules/kubernetes/aws"
  prefix             = local.full_prefix
  environment        = var.environment
  region             = var.region
  availability_zones = var.availability_zones
  kubernetes_version = var.kubernetes_version
  node_instance_type = var.node_instance_type
  node_min_size      = var.node_min_size
  node_max_size      = var.node_max_size
  node_desired_size  = var.node_desired_size
  tags               = local.tags
}

# Security group used by the Postgres + OpenSearch instances so they
# accept traffic from the EKS node CIDR(s).
resource "aws_security_group" "datastore" {
  name        = "${local.full_prefix}-datastore"
  description = "Postgres + OpenSearch inbound from EKS workers."
  vpc_id      = module.kubernetes.vpc_id

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = [for s in module.kubernetes.private_subnet_ids : "10.42.0.0/16"]
    description     = "VPC-internal"
  }
  egress {
    from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

module "database" {
  source         = "../../modules/database/aws"
  prefix         = local.full_prefix
  environment    = var.environment
  vpc_id         = module.kubernetes.vpc_id
  subnet_ids     = module.kubernetes.private_subnet_ids
  allowed_cidrs  = ["10.42.0.0/16"]
  instance_class = var.db_instance_class
  allocated_storage_gb = var.db_allocated_storage
  enable_replica = var.enable_db_replica
  tags           = local.tags

  depends_on = [module.kubernetes]
}

module "object_storage" {
  source           = "../../modules/object-storage/aws"
  bucket_prefix    = local.full_prefix
  environment      = var.environment
  region           = var.region
  object_lock_days = var.object_lock_days
  tags             = local.tags
}

module "opensearch" {
  source           = "../../modules/opensearch/aws"
  domain_name      = "${local.full_prefix}-os"
  environment      = var.environment
  instance_type    = var.opensearch_instance_type
  volume_size_gb   = var.opensearch_volume_size
  subnet_ids       = module.kubernetes.private_subnet_ids
  security_group_ids = [aws_security_group.datastore.id]
  tags             = local.tags
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
