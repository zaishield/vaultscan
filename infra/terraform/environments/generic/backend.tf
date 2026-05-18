# Default to local state for the BYO path — operators on bare metal
# / on-prem typically don't want to depend on a cloud bucket. Replace
# this block with a remote backend (s3/gcs/azurerm/consul/http) if
# you're running shared state.

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
