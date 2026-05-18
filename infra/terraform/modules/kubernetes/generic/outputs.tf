output "cluster_name"      { value = var.cluster_name }
output "kubeconfig_path"   { value = var.kubeconfig_path }
output "cluster_endpoint"  { value = "" }
output "cluster_ca"        { value = ""; sensitive = true }
output "vpc_id"            { value = "" }
output "private_subnet_ids" { value = [] }
output "oidc_provider_arn" { value = "" }
