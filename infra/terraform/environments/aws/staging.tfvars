environment = "staging"
region      = "eu-west-1"
prefix      = "vaultscan"

availability_zones = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]

node_instance_type = "m6i.large"
node_min_size      = 2
node_max_size      = 6
node_desired_size  = 3

db_instance_class    = "db.m6i.large"
db_allocated_storage = 100
enable_db_replica    = false

opensearch_instance_type = "m6g.large.search"
opensearch_volume_size   = 50

object_lock_days = 90

api_public_url = "https://api-staging.vaultscan.zaishield.com"
