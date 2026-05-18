output "cluster_name"      { value = azurerm_kubernetes_cluster.aks.name }
output "cluster_endpoint"  { value = azurerm_kubernetes_cluster.aks.kube_config[0].host }
output "cluster_ca" {
  value     = azurerm_kubernetes_cluster.aks.kube_config[0].cluster_ca_certificate
  sensitive = true
}
output "kubeconfig_path"   { value = local_file.kubeconfig.filename }
output "vpc_id"            { value = azurerm_virtual_network.vnet.id }
output "private_subnet_ids" { value = [azurerm_subnet.aks.id] }
output "oidc_provider_arn" {
  value       = ""
  description = "Azure uses Workload Identity, not OIDC ARNs — empty for shape compatibility."
}
output "resource_group_name" { value = azurerm_resource_group.rg.name }
