# State backend. Pre-create the bucket + DynamoDB lock table outside
# this composition (or via a bootstrap workspace). Edit the values
# below to match.

terraform {
  backend "s3" {
    bucket         = "vaultscan-tfstate"           # CHANGE ME
    key            = "vaultscan/aws/terraform.tfstate"
    region         = "eu-west-1"                   # CHANGE ME
    dynamodb_table = "vaultscan-tflocks"           # CHANGE ME
    encrypt        = true
  }
}
