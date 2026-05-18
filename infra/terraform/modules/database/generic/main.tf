# Generic in-cluster Postgres (bitnami chart). Use for BYO clusters
# where there's no managed-Postgres service to point at — bare metal,
# on-prem, k3s, kind.
#
# NOT recommended for production: storage is whatever StorageClass
# the cluster offers; HA + backups + monitoring are operator-managed.
# Use a managed service in any cloud you have one available.

terraform {
  required_version = ">= 1.5"
  required_providers {
    helm       = { source = "hashicorp/helm",       version = ">= 2.13, < 3.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,  < 4.0" }
  }
}

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "helm_release" "postgres" {
  name             = "${var.prefix}-postgres"
  repository       = "https://charts.bitnami.com/bitnami"
  chart            = "postgresql"
  version          = var.chart_version
  namespace        = var.kubernetes_namespace
  create_namespace = true

  values = [yamlencode({
    auth = {
      username         = "vaultscan"
      password         = random_password.db.result
      database         = "vaultscan"
      postgresPassword = random_password.db.result
    }
    architecture = var.enable_replica ? "replication" : "standalone"
    primary = {
      persistence  = { size = "${var.storage_gb}Gi" }
      resources    = var.resources_primary
    }
    readReplicas = var.enable_replica ? {
      replicaCount = 1
      persistence  = { size = "${var.storage_gb}Gi" }
    } : null
    metrics = { enabled = true }
  })]
}

resource "kubernetes_secret_v1" "dsn" {
  metadata {
    name      = "${var.prefix}-db"
    namespace = var.kubernetes_namespace
  }
  data = {
    VAULTSCAN_DATABASE_URL = "postgres://vaultscan:${random_password.db.result}@${var.prefix}-postgres-postgresql.${var.kubernetes_namespace}.svc.cluster.local:5432/vaultscan?sslmode=disable"
    VAULTSCAN_DATABASE_REPLICA_URL = var.enable_replica ? "postgres://vaultscan:${random_password.db.result}@${var.prefix}-postgres-postgresql-read.${var.kubernetes_namespace}.svc.cluster.local:5432/vaultscan?sslmode=disable" : ""
  }
  type = "Opaque"

  depends_on = [helm_release.postgres]
}
