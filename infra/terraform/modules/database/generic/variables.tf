variable "prefix"      { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}

variable "chart_version"  { type = string; default = "15.5.20" }
variable "storage_gb"     { type = number; default = 50 }
variable "enable_replica" { type = bool;   default = false }
variable "kubernetes_namespace" { type = string; default = "vaultscan" }

variable "resources_primary" {
  type    = any
  default = {
    requests = { cpu = "500m", memory = "1Gi" }
    limits   = { cpu = "2",    memory = "4Gi" }
  }
}
