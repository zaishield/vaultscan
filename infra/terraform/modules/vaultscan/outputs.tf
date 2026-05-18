output "release_name" { value = helm_release.vaultscan.name }
output "namespace"    { value = helm_release.vaultscan.namespace }
output "chart_version" { value = helm_release.vaultscan.metadata[0].version }
output "consolidated_secret_name" { value = kubernetes_secret_v1.consolidated.metadata[0].name }
