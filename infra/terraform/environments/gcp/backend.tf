terraform {
  backend "gcs" {
    bucket = "vaultscan-tfstate"         # CHANGE ME — pre-create
    prefix = "vaultscan/gcp"
  }
}
