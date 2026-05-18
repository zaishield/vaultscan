variable "domain_name" { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "engine_version" { type = string; default = "OpenSearch_2.13" }
variable "instance_type"  { type = string; default = "m6g.large.search" }
variable "volume_size_gb" { type = number; default = 100 }
variable "subnet_ids"        { type = list(string) }
variable "security_group_ids" { type = list(string) }
variable "tags"              { type = map(string); default = {} }
