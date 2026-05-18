variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}

variable "region"   { type = string }
variable "prefix"   { type = string; default = "vaultscan" }

variable "availability_zones" {
  type    = list(string)
  default = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
}

variable "kubernetes_version" { type = string; default = "1.30" }
variable "node_instance_type" { type = string; default = "m6i.xlarge" }
variable "node_min_size"      { type = number; default = 2 }
variable "node_max_size"      { type = number; default = 10 }
variable "node_desired_size"  { type = number; default = 3 }

variable "db_instance_class"    { type = string; default = "db.m6i.large" }
variable "db_allocated_storage" { type = number; default = 100 }
variable "enable_db_replica"    { type = bool;   default = false }

variable "opensearch_instance_type" { type = string; default = "m6g.large.search" }
variable "opensearch_volume_size"   { type = number; default = 100 }

variable "object_lock_days" { type = number; default = 365 }

variable "api_public_url" { type = string; default = "" }
