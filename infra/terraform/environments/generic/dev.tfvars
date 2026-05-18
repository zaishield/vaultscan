environment        = "dev"
cluster_name       = "vaultscan-dev"
kubeconfig_path    = "~/.kube/config"
# When running locally via tools/scripts/local-cluster.sh, the
# context name is "kind-vaultscan-dev". Override for any other
# kubeconfig (empty = current-context).
kubeconfig_context = "kind-vaultscan-dev"
db_storage_gb      = 20
object_store_gb    = 20
enable_db_replica  = false
