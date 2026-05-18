# AWS EKS — uses the community terraform-aws-modules/eks/aws module
# rather than re-implementing 2000 lines of IAM + node group glue.
#
# Returns the kubeconfig + cluster name so downstream modules can
# install Helm charts into the cluster.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws        = { source = "hashicorp/aws",        version = ">= 5.50, < 6.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "${var.prefix}-vpc"
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway     = true
  single_nat_gateway     = var.environment != "prod"   # prod = NAT per AZ
  enable_dns_hostnames   = true
  enable_dns_support     = true

  # Required EKS subnet tags so the LB controller picks them up.
  public_subnet_tags  = { "kubernetes.io/role/elb" = "1" }
  private_subnet_tags = { "kubernetes.io/role/internal-elb" = "1" }

  tags = local.common_tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.20"

  cluster_name    = "${var.prefix}-eks"
  cluster_version = var.kubernetes_version

  vpc_id                          = module.vpc.vpc_id
  subnet_ids                      = module.vpc.private_subnets
  cluster_endpoint_public_access  = var.cluster_endpoint_public_access
  cluster_endpoint_private_access = true

  # Use IRSA + IAM-bound SAs throughout.
  enable_irsa = true

  cluster_addons = {
    coredns                = { most_recent = true }
    kube-proxy             = { most_recent = true }
    vpc-cni                = { most_recent = true }
    aws-ebs-csi-driver     = { most_recent = true }
  }

  eks_managed_node_groups = {
    workers = {
      min_size     = var.node_min_size
      max_size     = var.node_max_size
      desired_size = var.node_desired_size

      instance_types = [var.node_instance_type]
      capacity_type  = var.node_capacity_type   # ON_DEMAND | SPOT

      labels = {
        "vaultscan.io/tier" = "workload"
      }

      tags = local.common_tags
    }
  }

  tags = local.common_tags
}

locals {
  common_tags = merge(var.tags, {
    "vaultscan.io/environment" = var.environment
    "vaultscan.io/managed-by"  = "terraform"
  })
}

# kubeconfig is built from the EKS cluster auth output. The
# `kubernetes` + `helm` providers in the parent composition can
# consume the returned `cluster_endpoint` + `cluster_ca` +
# `aws-iam-authenticator` exec auth.
resource "local_file" "kubeconfig" {
  filename        = "${path.root}/.kubeconfig-${var.prefix}-${var.environment}"
  file_permission = "0600"
  content = templatefile("${path.module}/kubeconfig.tpl", {
    cluster_name = module.eks.cluster_name
    endpoint     = module.eks.cluster_endpoint
    ca           = module.eks.cluster_certificate_authority_data
    region       = var.region
  })
}
