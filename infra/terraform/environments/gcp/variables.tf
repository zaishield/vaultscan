variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}

variable "project_id" { type = string }
variable "region"     { type = string;  default = "europe-west1" }
variable "zones"      { type = list(string); default = ["europe-west1-b", "europe-west1-c", "europe-west1-d"] }
variable "prefix"     { type = string;  default = "vaultscan" }

variable "kubernetes_version" { type = string; default = "latest" }
variable "node_machine_type"  { type = string; default = "e2-standard-4" }
variable "node_min_size"      { type = number; default = 2 }
variable "node_max_size"      { type = number; default = 10 }
variable "node_desired_size"  { type = number; default = 3 }

variable "db_tier"            { type = string; default = "db-custom-2-7680" }
variable "db_storage_gb"      { type = number; default = 100 }
variable "enable_db_replica"  { type = bool;   default = false }

variable "api_public_url"     { type = string; default = "" }
