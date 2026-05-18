environment = "prod"
region      = "eu-west-1"
prefix      = "vaultscan"

availability_zones = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]

node_instance_type = "m6i.2xlarge"
node_min_size      = 3
node_max_size      = 18
node_desired_size  = 6

db_instance_class    = "db.m6i.xlarge"
db_allocated_storage = 500
enable_db_replica    = true

opensearch_instance_type = "m6g.xlarge.search"
opensearch_volume_size   = 500

object_lock_days = 2555    # 7 years for SOC2 / ISO27001 retention

api_public_url = "https://api.vaultscan.zaishield.com"
