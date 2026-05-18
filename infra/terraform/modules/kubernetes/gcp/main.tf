# GCP GKE — uses terraform-google-modules/kubernetes-engine.
# Output shape matches modules/kubernetes/aws/ so the downstream
# composition can swap clouds without code changes.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google     = { source = "hashicorp/google",     version = ">= 5.30, < 6.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
  }
}

resource "google_compute_network" "vpc" {
  name                    = "${var.prefix}-vpc"
  auto_create_subnetworks = false
  project                 = var.project_id
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.prefix}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.vpc.self_link
  project       = var.project_id

  # Pod + service ranges for VPC-native (IP aliasing) — required
  # for GKE Autopilot and recommended for Standard.
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }
}

module "gke" {
  source                     = "terraform-google-modules/kubernetes-engine/google"
  version                    = "~> 31.0"
  project_id                 = var.project_id
  name                       = "${var.prefix}-gke"
  region                     = var.region
  zones                      = var.zones
  network                    = google_compute_network.vpc.name
  subnetwork                 = google_compute_subnetwork.subnet.name
  ip_range_pods              = "pods"
  ip_range_services          = "services"
  kubernetes_version         = var.kubernetes_version
  release_channel            = var.release_channel
  remove_default_node_pool   = true
  enable_private_endpoint    = !var.cluster_endpoint_public_access
  enable_private_nodes       = true
  master_ipv4_cidr_block     = "172.16.0.0/28"
  network_policy             = true
  horizontal_pod_autoscaling = true
  http_load_balancing        = true

  node_pools = [
    {
      name               = "workers"
      machine_type       = var.node_machine_type
      min_count          = var.node_min_size
      max_count          = var.node_max_size
      initial_node_count = var.node_desired_size
      preemptible        = var.environment != "prod"
      auto_repair        = true
      auto_upgrade       = true
      disk_size_gb       = 100
      disk_type          = "pd-balanced"
    }
  ]
}

resource "local_file" "kubeconfig" {
  filename        = "${path.root}/.kubeconfig-${var.prefix}-${var.environment}"
  file_permission = "0600"
  content = templatefile("${path.module}/kubeconfig.tpl", {
    cluster_name = module.gke.name
    endpoint     = "https://${module.gke.endpoint}"
    ca           = module.gke.ca_certificate
    project      = var.project_id
    region       = var.region
  })
}
