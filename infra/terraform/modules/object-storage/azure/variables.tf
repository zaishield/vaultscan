variable "bucket_prefix" { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "resource_group_name"  { type = string }
variable "location"             { type = string; default = "westeurope" }
variable "kubernetes_namespace" { type = string; default = "vaultscan" }
variable "tags"                 { type = map(string); default = {} }
