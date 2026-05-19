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

# DB password rotation token: bump this string to force regeneration
# of the random_password.db keepers (which then propagates through to
# the RDS instance + the Secrets Manager value). Leave alone to keep
# the existing password. Documented in the runbook so operators know
# this is the rotation lever, not a "regenerate every apply" footgun.
variable "db_password_rotation_token" {
  type        = string
  default     = "initial"
  description = "Bump to rotate the DB master password; unchanged value keeps the current password."
}
variable "kms_key_id" {
  type        = string
  default     = ""
  description = "Optional CMK ARN for RDS storage_encrypted. Empty = use the AWS-managed default key (shared with other AWS services in the account). Production deployments that want true key-control should pass a customer-managed key here."
}
