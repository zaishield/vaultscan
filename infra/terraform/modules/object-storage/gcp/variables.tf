variable "bucket_prefix" { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "project_id"     { type = string }
variable "location"       { type = string; default = "EU" }
variable "retention_seconds" { type = number; default = 31536000 }  # 1 year
variable "kms_key_name"   { type = string; default = null }
variable "kubernetes_namespace" { type = string; default = "vaultscan" }
variable "labels"         { type = map(string); default = {} }
