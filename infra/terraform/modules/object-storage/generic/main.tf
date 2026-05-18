# Generic in-cluster MinIO via the bitnami chart. S3-compatible
# endpoint with the same env-var contract as the cloud modules.

terraform {
  required_version = ">= 1.5"
  required_providers {
    helm       = { source = "hashicorp/helm",       version = ">= 2.13, < 3.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,  < 4.0" }
  }
}

resource "random_password" "secret" {
  length  = 40
  special = false
}

resource "helm_release" "minio" {
  name             = "${var.bucket_prefix}-minio"
  repository       = "https://charts.bitnami.com/bitnami"
  chart            = "minio"
  version          = var.chart_version
  namespace        = var.kubernetes_namespace
  create_namespace = true

  values = [yamlencode({
    auth = {
      rootUser     = "vaultscan"
      rootPassword = random_password.secret.result
    }
    mode             = var.environment == "prod" ? "distributed" : "standalone"
    statefulset      = { replicaCount = var.environment == "prod" ? 4 : 1 }
    persistence      = { size = "${var.storage_gb}Gi" }
    defaultBuckets   = "vaultscan-evidence"
    metrics          = { prometheusRule = { enabled = false } }
  })]
}

resource "kubernetes_secret_v1" "creds" {
  metadata {
    name      = "${var.bucket_prefix}-object-store"
    namespace = var.kubernetes_namespace
  }
  data = {
    VAULTSCAN_OBJECT_STORE_URL    = "http://${var.bucket_prefix}-minio.${var.kubernetes_namespace}.svc.cluster.local:9000"
    VAULTSCAN_OBJECT_STORE_BUCKET = "vaultscan-evidence"
    VAULTSCAN_OBJECT_STORE_REGION = "us-east-1"
    VAULTSCAN_OBJECT_STORE_KEY    = "vaultscan"
    VAULTSCAN_OBJECT_STORE_SECRET = random_password.secret.result
  }
  type = "Opaque"

  depends_on = [helm_release.minio]
}
