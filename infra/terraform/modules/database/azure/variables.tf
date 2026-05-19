variable "prefix"      { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "resource_group_name" { type = string }
variable "location"            { type = string; default = "westeurope" }
variable "zone"                { type = string; default = "1" }
variable "engine_version"      { type = string; default = "16" }
variable "sku_name"            { type = string; default = "GP_Standard_D2s_v3" }
variable "storage_mb"          { type = number; default = 131072 }
variable "delegated_subnet_id" { type = string; default = null }
variable "private_dns_zone_id" { type = string; default = null }
variable "enable_replica"      { type = bool;   default = false }
variable "kubernetes_namespace" { type = string; default = "vaultscan" }
variable "tags"                { type = map(string); default = {} }
variable "db_password_rotation_token" {
  type        = string
  default     = "initial"
  description = "Bump to rotate the DB master password; unchanged value keeps the current password."
}
