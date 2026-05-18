variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}

variable "prefix"     { type = string; default = "vaultscan" }

variable "kubeconfig_path" {
  type        = string
  description = "Path to a kubeconfig with cluster-admin on the target cluster."
  default     = "~/.kube/config"
}

variable "kubeconfig_context" {
  type        = string
  description = "Context inside the kubeconfig to use. Empty = current-context."
  default     = ""
}

variable "cluster_name" {
  type        = string
  description = "Logical name for this cluster (used in resource prefixes)."
  default     = "vaultscan-byo"
}

variable "db_storage_gb"     { type = number; default = 50 }
variable "enable_db_replica" { type = bool;   default = false }

variable "object_store_gb"   { type = number; default = 100 }

variable "api_public_url"    { type = string; default = "" }
variable "region"            { type = string; default = "" }

variable "local_overrides_enabled" {
  type        = bool
  description = "Apply infra/terraform/environments/generic/local-overrides.yaml on top of the env overlay. Set true when running on a local kind cluster."
  default     = false
}
