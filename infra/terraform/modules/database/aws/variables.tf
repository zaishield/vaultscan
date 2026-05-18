variable "prefix"      { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}

variable "vpc_id"         { type = string }
variable "subnet_ids"     { type = list(string) }
variable "allowed_cidrs"  { type = list(string); default = ["10.0.0.0/8"] }

variable "engine_version"        { type = string; default = "16.3" }
variable "instance_class"        { type = string; default = "db.m6i.large" }
variable "replica_instance_class" { type = string; default = "db.m6i.large" }
variable "allocated_storage_gb"  { type = number; default = 100 }
variable "enable_replica"        { type = bool;   default = false }

variable "kubernetes_namespace"  { type = string; default = "vaultscan" }
variable "tags"                  { type = map(string); default = {} }
