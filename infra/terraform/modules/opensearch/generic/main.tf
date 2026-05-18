# OpenSearch operator path. Works on any Kubernetes cluster
# (GCP, Azure, on-prem, bare metal). Installs the OpenSearch operator
# + a single OpenSearchCluster custom resource.

terraform {
  required_version = ">= 1.5"
  required_providers {
    helm       = { source = "hashicorp/helm",       version = ">= 2.13, < 3.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
  }
}

resource "helm_release" "operator" {
  name             = "opensearch-operator"
  repository       = "https://opensearch-project.github.io/opensearch-k8s-operator"
  chart            = "opensearch-operator"
  version          = var.operator_chart_version
  namespace        = var.operator_namespace
  create_namespace = true
}

resource "kubernetes_manifest" "cluster" {
  manifest = {
    apiVersion = "opensearch.opster.io/v1"
    kind       = "OpenSearchCluster"
    metadata = {
      name      = var.cluster_name
      namespace = var.cluster_namespace
    }
    spec = {
      general = {
        version     = var.opensearch_version
        serviceName = var.cluster_name
        httpPort    = 9200
      }
      dashboards = {
        enable  = false
        version = var.opensearch_version
      }
      nodePools = [
        {
          component    = "masters"
          replicas     = var.environment == "prod" ? 3 : 1
          diskSize     = "${var.disk_gb}Gi"
          roles        = ["cluster_manager", "data", "ingest"]
          resources = {
            requests = { cpu = "500m", memory = "2Gi" }
            limits   = { cpu = "2",    memory = "4Gi" }
          }
        }
      ]
    }
  }

  depends_on = [helm_release.operator]
}
