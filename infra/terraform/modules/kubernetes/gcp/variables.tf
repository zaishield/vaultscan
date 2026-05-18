variable "prefix" {
  type        = string
  description = "Resource-name prefix (e.g. vaultscan-eu-prod)."
}

variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}

variable "project_id" {
  type        = string
  description = "GCP project to create resources in."
}

variable "region" {
  type    = string
  default = "europe-west1"
}

variable "zones" {
  type    = list(string)
  default = ["europe-west1-b", "europe-west1-c", "europe-west1-d"]
}

variable "subnet_cidr" {
  type    = string
  default = "10.42.0.0/20"
}

variable "pods_cidr" {
  type    = string
  default = "10.43.0.0/16"
}

variable "services_cidr" {
  type    = string
  default = "10.44.0.0/20"
}

variable "kubernetes_version" {
  type    = string
  default = "latest"
}

variable "release_channel" {
  type    = string
  default = "REGULAR"
}

variable "cluster_endpoint_public_access" {
  type    = bool
  default = true
}

variable "node_machine_type" {
  type    = string
  default = "e2-standard-4"
}

variable "node_min_size" {
  type    = number
  default = 2
}

variable "node_max_size" {
  type    = number
  default = 10
}

variable "node_desired_size" {
  type    = number
  default = 3
}

variable "tags" {
  type    = map(string)
  default = {}
}
