# Generic Kubernetes — bring your own cluster.
#
# This module doesn't provision anything; it just normalises the
# kubeconfig path so downstream modules see the same shape as the
# cloud-specific siblings. Use this for:
#   - bare metal / on-prem clusters (Rancher, OKD, vanilla kubeadm)
#   - k3s / k3d
#   - kind (CI)
#   - clusters provisioned out-of-band (different Terraform repo)
#
# The data source confirms the cluster is reachable before the
# composition tries to apply Helm charts.

terraform {
  required_version = ">= 1.5"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
  }
}

data "kubernetes_namespace_v1" "default" {
  metadata { name = "default" }
}
