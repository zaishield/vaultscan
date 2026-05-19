variable "prefix"            { type = string }
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be dev|staging|uat|prod."
  }
}
variable "location"           { type = string;  default = "westeurope" }
variable "availability_zones" { type = list(string); default = ["1", "2", "3"] }
variable "vnet_cidr"          { type = string;  default = "10.42.0.0/16" }
variable "aks_subnet_cidr"    { type = string;  default = "10.42.0.0/20" }
variable "kubernetes_version" { type = string;  default = "1.30" }
variable "cluster_endpoint_public_access" {
  description = "Whether the AKS API server is reachable from the public internet. Default FALSE — production AKS uses a private cluster + Azure Bastion."
  type    = bool
  default = false
}
variable "api_server_authorized_ip_ranges" {
  description = "When cluster_endpoint_public_access = true, the operator IP allowlist. Empty list with public_access=true is rejected — fail loud rather than expose the API server to 0.0.0.0/0."
  type    = list(string)
  default = []
}
variable "node_vm_size"       { type = string;  default = "Standard_D4s_v5" }
variable "node_min_size"      { type = number;  default = 2 }
variable "node_max_size"      { type = number;  default = 10 }
variable "node_desired_size"  { type = number;  default = 3 }
variable "tags"               { type = map(string); default = {} }
