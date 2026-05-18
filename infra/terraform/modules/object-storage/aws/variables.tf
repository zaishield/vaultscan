variable "bucket_prefix" { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "region"               { type = string }
variable "object_lock_days"     { type = number; default = 365 }
variable "kubernetes_namespace" { type = string; default = "vaultscan" }
variable "tags"                 { type = map(string); default = {} }
