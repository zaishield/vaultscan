variable "cluster_name" { type = string; default = "vaultscan-os" }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "operator_namespace"     { type = string; default = "opensearch-operator-system" }
variable "operator_chart_version" { type = string; default = "2.6.0" }
variable "cluster_namespace"      { type = string; default = "vaultscan" }
variable "opensearch_version"     { type = string; default = "2.13.0" }
variable "disk_gb"                { type = number; default = 50 }
