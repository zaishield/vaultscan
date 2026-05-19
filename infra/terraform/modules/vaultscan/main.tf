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
    tls        = { source = "hashicorp/tls",        version = ">= 4.0,  < 5.0" }
  }
}

resource "random_password" "jwt" {
  length  = 64
  special = false

  keepers = {
    rotation_token = var.jwt_rotation_token
  }
}

resource "random_password" "evidence_key" {
  length  = 44
  special = false

  keepers = {
    rotation_token = var.evidence_key_rotation_token
  }
}

# Job-signing key — Blueprint §12.3. RSA 4096 PEM that scanner-worker
# uses to sign each per-tool dispatch; agents verify via cosign-pinned
# public key. Generated here so the helm chart's
# secrets.existingSecret has VAULTSCAN_JOB_SIGNING_KEY set; prior to
# this addition the scanner-worker booted with a missing env var and
# failed at scanorch.NewSigner(...) construction time.
resource "tls_private_key" "job_signing" {
  algorithm = "RSA"
  rsa_bits  = 4096

  lifecycle {
    # Avoid surprise rotation on apply — operators rotate via
    # taint+apply or by importing a manually-rotated key.
    ignore_changes = [algorithm, rsa_bits]
  }
}

resource "kubernetes_namespace_v1" "ns" {
  metadata { name = var.namespace }

  lifecycle {
    ignore_changes = [metadata[0].labels, metadata[0].annotations]
  }
}

# Consolidated env Secret. Composed directly from upstream-module
# outputs (database_secret_data + object_store_secret_data) — no
# data-source chain needed, so the dependency graph stays explicit
# and Terraform doesn't emit sensitive-merge noise on every plan.
resource "kubernetes_secret_v1" "consolidated" {
  metadata {
    name      = "${var.release_name}-env"
    namespace = kubernetes_namespace_v1.ns.metadata[0].name
  }
  data = merge(
    var.database_secret_data,
    var.object_store_secret_data,
    {
      VAULTSCAN_JWT_SECRET          = random_password.jwt.result
      VAULTSCAN_EVIDENCE_MASTER_KEY = base64encode(random_password.evidence_key.result)
      VAULTSCAN_JOB_SIGNING_KEY     = tls_private_key.job_signing.private_key_pem
      VAULTSCAN_JOB_SIGNING_KEY_ID  = "job-signing-${substr(md5(tls_private_key.job_signing.public_key_pem), 0, 12)}"
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
    [for p in var.extra_values_files : file(p)],
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
