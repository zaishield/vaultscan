# AWS OpenSearch Service.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.50, < 6.0" }
    random = { source = "hashicorp/random", version = ">= 3.6, < 4.0" }
  }
}

resource "random_password" "master" {
  length  = 24
  special = false
}

resource "aws_opensearch_domain" "this" {
  domain_name    = var.domain_name
  engine_version = var.engine_version

  cluster_config {
    instance_type            = var.instance_type
    instance_count           = var.environment == "prod" ? 3 : 1
    zone_awareness_enabled   = var.environment == "prod"
    dedicated_master_enabled = var.environment == "prod"
    dedicated_master_type    = var.environment == "prod" ? "m6g.large.search" : null
    dedicated_master_count   = var.environment == "prod" ? 3 : null
  }

  ebs_options {
    ebs_enabled = true
    volume_size = var.volume_size_gb
    volume_type = "gp3"
  }

  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = var.security_group_ids
  }

  encrypt_at_rest { enabled = true }
  node_to_node_encryption { enabled = true }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
      master_user_password = random_password.master.result
    }
  }

  tags = var.tags
}
