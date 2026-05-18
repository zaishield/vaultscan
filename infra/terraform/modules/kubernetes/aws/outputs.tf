# Outputs are deliberately cloud-agnostic so the downstream
# vaultscan module can consume them identically regardless of which
# cloud rendered them.

output "cluster_name" {
  value = module.eks.cluster_name
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "cluster_ca" {
  value     = module.eks.cluster_certificate_authority_data
  sensitive = true
}

output "kubeconfig_path" {
  value = local_file.kubeconfig.filename
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnet_ids" {
  value = module.vpc.private_subnets
}

output "oidc_provider_arn" {
  description = "Pass to IRSA-backed pods (External Secrets Operator, etc.)."
  value       = module.eks.oidc_provider_arn
}
