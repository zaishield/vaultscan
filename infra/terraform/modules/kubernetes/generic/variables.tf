variable "prefix"      { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}

variable "kubeconfig_path" {
  type        = string
  description = "Path to a kubeconfig with cluster-admin on the target cluster."
}

variable "cluster_name" {
  type        = string
  description = "Context name inside the kubeconfig."
}
