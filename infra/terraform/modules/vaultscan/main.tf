# Cloud-agnostic VaultScan deploy. Consumes the cloud-agnostic
# outputs of the kubernetes/, database/, object-storage/, opensearch/
# modules and renders the Helm chart from ../../../helm/vaultscan.
#
# Treats secrets uniformly: each upstream module creates its own
# k8s Secret; this module emits ONE consolidated Secret named after
# the release so the chart's secrets.existingSecret can point at it.

terraform {
  required_version = ">= 1.5"
  required_providers {
    helm       = { source = "hashicorp/helm",       version = ">= 2.13, < 3.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,  < 4.0" }
  }
}

resource "random_password" "jwt" {
  length  = 64
  special = false
}

resource "random_password" "evidence_key" {
  length  = 44
  special = false
}

# Collect the upstream-module secret data into one chart-friendly
# Secret. We read each by data block; the upstream secrets are
# referenced by name so we don't duplicate their contents in state.
data "kubernetes_secret_v1" "db" {
  metadata {
    name      = var.database_dsn_secret_name
    namespace = var.namespace
  }
}

data "kubernetes_secret_v1" "object_store" {
  metadata {
    name      = var.object_store_credentials_secret_name
    namespace = var.namespace
  }
}

resource "kubernetes_namespace_v1" "ns" {
  metadata { name = var.namespace }

  lifecycle {
    ignore_changes = [metadata[0].labels, metadata[0].annotations]
  }
}

resource "kubernetes_secret_v1" "consolidated" {
  metadata {
    name      = "${var.release_name}-env"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
  }
  data = merge(
    data.kubernetes_secret_v1.db.data,
    data.kubernetes_secret_v1.object_store.data,
    {
      VAULTSCAN_JWT_SECRET          = random_password.jwt.result
      VAULTSCAN_EVIDENCE_MASTER_KEY = base64encode(random_password.evidence_key.result)
      VAULTSCAN_OPENSEARCH_URL      = var.opensearch_endpoint
    }
  )
  type = "Opaque"
}

resource "helm_release" "vaultscan" {
  name       = var.release_name
  chart      = var.chart_path
  namespace  = kubernetes_namespace_v1.ns.metadata[0].name
  values = concat(
    [file("${var.chart_path}/values-${var.environment}.yaml")],
    var.extra_values_files,
    [yamlencode({
      global = {
        region = var.region
      }
      api = {
        publicURL = var.api_public_url
      }
      secrets = {
        existingSecret = kubernetes_secret_v1.consolidated.metadata[0].name
      }
      databases = {
        external = {
          postgresURL        = "" # served from the consolidated Secret
          postgresReplicaURL = ""
          opensearchURL      = var.opensearch_endpoint
          objectStoreURL     = "" # served from the consolidated Secret
          objectStoreBucket  = var.object_store_bucket
        }
      }
    })],
    var.helm_value_overrides,
  )

  depends_on = [kubernetes_secret_v1.consolidated]
}
