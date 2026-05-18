variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}

variable "location" { type = string; default = "westeurope" }
variable "prefix"   { type = string; default = "vaultscan" }

variable "availability_zones" { type = list(string); default = ["1", "2", "3"] }
variable "kubernetes_version" { type = string; default = "1.30" }
variable "node_vm_size"       { type = string; default = "Standard_D4s_v5" }
variable "node_min_size"      { type = number; default = 2 }
variable "node_max_size"      { type = number; default = 10 }
variable "node_desired_size"  { type = number; default = 3 }

variable "db_sku_name"        { type = string; default = "GP_Standard_D2s_v3" }
variable "db_storage_mb"      { type = number; default = 131072 }
variable "enable_db_replica"  { type = bool;   default = false }

variable "api_public_url" { type = string; default = "" }
