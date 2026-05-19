variable "prefix"      { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "project_id"      { type = string }
variable "region"          { type = string; default = "europe-west1" }
variable "engine_version"  { type = string; default = "POSTGRES_16" }
variable "tier"            { type = string; default = "db-custom-2-7680" }
variable "replica_tier"    { type = string; default = "db-custom-1-3840" }
variable "allocated_storage_gb" { type = number; default = 100 }
variable "vpc_self_link"   { type = string }
variable "enable_replica"  { type = bool; default = false }
variable "kubernetes_namespace" { type = string; default = "vaultscan" }
variable "tags"            { type = map(string); default = {} }
variable "db_password_rotation_token" {
  type        = string
  default     = "initial"
  description = "Bump to rotate the DB master password; unchanged value keeps the current password."
}
