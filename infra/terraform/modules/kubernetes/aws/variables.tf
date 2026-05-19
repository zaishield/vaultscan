variable "prefix" {
  description = "Name prefix for AWS resources (e.g. vaultscan-eu-prod)."
  type        = string
}

variable "environment" {
  description = "Environment label: dev | staging | uat | prod."
  type        = string
  validation {
    condition     = contains(["dev", "staging", "uat", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, uat, prod."
  }
}

variable "region" {
  description = "AWS region (e.g. eu-west-1)."
  type        = string
}

variable "availability_zones" {
  description = "AZs to spread the cluster across. Prod typically uses 3."
  type        = list(string)
}

variable "vpc_cidr" {
  description = "CIDR for the new VPC. Pick something that doesn't overlap your existing networks."
  type        = string
  default     = "10.42.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "Private-subnet CIDRs, one per AZ."
  type        = list(string)
  default     = ["10.42.1.0/24", "10.42.2.0/24", "10.42.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "Public-subnet CIDRs, one per AZ."
  type        = list(string)
  default     = ["10.42.101.0/24", "10.42.102.0/24", "10.42.103.0/24"]
}

variable "kubernetes_version" {
  description = "EKS control plane version."
  type        = string
  default     = "1.30"
}

variable "cluster_endpoint_public_access" {
  description = "Whether the EKS control plane is reachable from the public internet. Default FALSE — production clusters MUST go through a bastion or VPN. Flip true ONLY when paired with cluster_endpoint_public_access_cidrs to allowlist operator IPs."
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "When cluster_endpoint_public_access = true, the operator IP allowlist. Empty list with public_access=true is REJECTED by the AWS API; we default to a sentinel that the AWS provider rejects so a misconfigured flip fails loud."
  type        = list(string)
  default     = []
}

variable "node_instance_type" {
  description = "EC2 instance type for worker nodes."
  type        = string
  default     = "m6i.xlarge"
}

variable "node_capacity_type" {
  description = "ON_DEMAND or SPOT. Prod = ON_DEMAND."
  type        = string
  default     = "ON_DEMAND"
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
  description = "Extra AWS tags to merge with the defaults."
  type        = map(string)
  default     = {}
}
