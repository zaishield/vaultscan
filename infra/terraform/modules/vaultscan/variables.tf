variable "release_name" { type = string; default = "vaultscan" }
variable "namespace"     { type = string; default = "vaultscan" }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "chart_path" {
  type        = string
  description = "Path to the helm chart on disk. Defaults to the repo's chart."
  default     = "../../../helm/vaultscan"
}

variable "region" {
  type        = string
  description = "Pod region for data-residency enforcement. Empty in single-region deployments."
  default     = ""
}

variable "api_public_url" { type = string; default = "" }

variable "database_dsn_secret_name"             { type = string }
variable "object_store_credentials_secret_name" { type = string }
variable "object_store_bucket"                  { type = string }
variable "opensearch_endpoint"                  { type = string }

variable "extra_values_files" {
  type        = list(string)
  description = "Additional values overlays the operator wants merged on top."
  default     = []
}

variable "helm_value_overrides" {
  type        = list(string)
  description = "Inline YAML strings appended to the helm release values list."
  default     = []
}
