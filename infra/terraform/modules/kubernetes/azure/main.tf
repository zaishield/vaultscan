# Azure AKS — matches the AWS/GCP module shape.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm    = { source = "hashicorp/azurerm",    version = ">= 3.100, < 4.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
  }
}

resource "azurerm_resource_group" "rg" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = local.common_tags
}

resource "azurerm_virtual_network" "vnet" {
  name                = "${var.prefix}-vnet"
  address_space       = [var.vnet_cidr]
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  tags                = local.common_tags
}

resource "azurerm_subnet" "aks" {
  name                 = "${var.prefix}-aks-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [var.aks_subnet_cidr]
}

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "${var.prefix}-aks"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  dns_prefix          = var.prefix
  kubernetes_version  = var.kubernetes_version
  sku_tier            = var.environment == "prod" ? "Standard" : "Free"

  default_node_pool {
    name                 = "workers"
    vm_size              = var.node_vm_size
    vnet_subnet_id       = azurerm_subnet.aks.id
    auto_scaling_enabled = true
    min_count            = var.node_min_size
    max_count            = var.node_max_size
    node_count           = var.node_desired_size
    type                 = "VirtualMachineScaleSets"
    zones                = var.availability_zones
    tags                 = local.common_tags
  }

  identity { type = "SystemAssigned" }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"
    load_balancer_sku = "standard"
  }

  private_cluster_enabled = !var.cluster_endpoint_public_access

  # When the API server endpoint is public, restrict to the operator
  # IP allowlist. Wires the var.api_server_authorized_ip_ranges
  # input that was previously declared but never plumbed through.
  dynamic "api_server_access_profile" {
    for_each = (var.cluster_endpoint_public_access && length(var.api_server_authorized_ip_ranges) > 0) ? [1] : []
    content {
      authorized_ip_ranges = var.api_server_authorized_ip_ranges
    }
  }

  tags = local.common_tags
}

locals {
  common_tags = merge(var.tags, {
    "vaultscan.io/environment" = var.environment
    "vaultscan.io/managed-by"  = "terraform"
  })
}

resource "local_file" "kubeconfig" {
  filename        = "${path.root}/.kubeconfig-${var.prefix}-${var.environment}"
  file_permission = "0600"
  content         = azurerm_kubernetes_cluster.aks.kube_config_raw
}
