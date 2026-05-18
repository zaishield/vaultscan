output "cluster_name" {
  value = module.gke.name
}

output "cluster_endpoint" {
  value = "https://${module.gke.endpoint}"
}

output "cluster_ca" {
  value     = module.gke.ca_certificate
  sensitive = true
}

output "kubeconfig_path" {
  value = local_file.kubeconfig.filename
}

output "vpc_id" {
  value = google_compute_network.vpc.self_link
}

output "private_subnet_ids" {
  value = [google_compute_subnetwork.subnet.self_link]
}

output "oidc_provider_arn" {
  value       = ""
  description = "GCP uses Workload Identity, not OIDC ARNs — this output is empty for shape compatibility."
}
