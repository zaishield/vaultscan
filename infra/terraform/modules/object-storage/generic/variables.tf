variable "bucket_prefix" { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "chart_version" { type = string; default = "14.6.30" }
variable "storage_gb"    { type = number; default = 100 }
variable "kubernetes_namespace" { type = string; default = "vaultscan" }
