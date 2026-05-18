# GCP Cloud Storage bucket + dedicated service account.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google     = { source = "hashicorp/google",     version = ">= 5.30, < 6.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,  < 4.0" }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "evidence" {
  name                        = "${var.bucket_prefix}-${random_id.suffix.hex}"
  location                    = var.location
  project                     = var.project_id
  uniform_bucket_level_access = true
  storage_class               = "STANDARD"
  force_destroy               = var.environment != "prod"

  versioning { enabled = true }

  retention_policy {
    retention_period = var.retention_seconds
    is_locked        = var.environment == "prod"
  }

  encryption {
    default_kms_key_name = var.kms_key_name
  }

  lifecycle_rule {
    condition { age = 30 }
    action    { type = "SetStorageClass"; storage_class = "NEARLINE" }
  }

  labels = var.labels
}

resource "google_service_account" "api" {
  account_id   = "${var.bucket_prefix}-${random_id.suffix.hex}"
  display_name = "VaultScan API bucket access (${var.environment})"
  project      = var.project_id
}

resource "google_storage_bucket_iam_member" "api" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.api.email}"
}

resource "google_service_account_key" "api" {
  service_account_id = google_service_account.api.name
}

resource "kubernetes_secret_v1" "creds" {
  metadata {
    name      = "${var.bucket_prefix}-object-store"
    namespace = var.kubernetes_namespace
  }
  data = {
    VAULTSCAN_OBJECT_STORE_URL    = "https://storage.googleapis.com"
    VAULTSCAN_OBJECT_STORE_BUCKET = google_storage_bucket.evidence.name
    VAULTSCAN_OBJECT_STORE_REGION = var.location
    VAULTSCAN_OBJECT_STORE_KEY    = google_service_account.api.email
    VAULTSCAN_OBJECT_STORE_SECRET = google_service_account_key.api.private_key
  }
  type = "Opaque"
}
