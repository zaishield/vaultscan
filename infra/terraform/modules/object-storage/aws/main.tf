# AWS S3 + dedicated IAM user for the API to authenticate as.
# Object lock (governance mode) + versioning enabled by default —
# evidence WORM enforcement relies on these.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws        = { source = "hashicorp/aws",        version = ">= 5.50, < 6.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.29, < 3.0" }
    random     = { source = "hashicorp/random",     version = ">= 3.6,  < 4.0" }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "evidence" {
  bucket        = "${var.bucket_prefix}-${random_id.suffix.hex}"
  force_destroy = var.environment != "prod"
  object_lock_enabled = true
  tags                = var.tags
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode  = "GOVERNANCE"
      days  = var.object_lock_days
    }
  }
}

resource "aws_iam_user" "api" {
  name = "${var.bucket_prefix}-${random_id.suffix.hex}-api"
  tags = var.tags
}

resource "aws_iam_access_key" "api" {
  user = aws_iam_user.api.name
}

data "aws_iam_policy_document" "api" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
  }
}

resource "aws_iam_user_policy" "api" {
  name   = "${aws_iam_user.api.name}-bucket-access"
  user   = aws_iam_user.api.name
  policy = data.aws_iam_policy_document.api.json
}

resource "kubernetes_secret_v1" "creds" {
  metadata {
    name      = "${var.bucket_prefix}-object-store"
    namespace = var.kubernetes_namespace
  }
  data = {
    VAULTSCAN_OBJECT_STORE_URL    = "https://s3.${var.region}.amazonaws.com"
    VAULTSCAN_OBJECT_STORE_BUCKET = aws_s3_bucket.evidence.bucket
    VAULTSCAN_OBJECT_STORE_REGION = var.region
    VAULTSCAN_OBJECT_STORE_KEY    = aws_iam_access_key.api.id
    VAULTSCAN_OBJECT_STORE_SECRET = aws_iam_access_key.api.secret
  }
  type = "Opaque"
}
