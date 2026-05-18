output "cluster_name"    { value = module.kubernetes.cluster_name }
output "kubeconfig_path" { value = module.kubernetes.kubeconfig_path }
output "db_endpoint"     { value = module.database.endpoint }
output "db_replica_endpoint" { value = module.database.replica_endpoint }
output "bucket_name"     { value = module.object_storage.bucket_name }
output "opensearch_endpoint" { value = module.opensearch.endpoint }
output "release_name"    { value = module.vaultscan.release_name }
output "namespace"       { value = module.vaultscan.namespace }
