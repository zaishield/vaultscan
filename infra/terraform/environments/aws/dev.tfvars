environment = "dev"
region      = "eu-west-1"
prefix      = "vaultscan"

availability_zones = ["eu-west-1a", "eu-west-1b"]

node_instance_type = "t3.large"
node_min_size      = 1
node_max_size      = 3
node_desired_size  = 2

db_instance_class    = "db.t3.medium"
db_allocated_storage = 50
enable_db_replica    = false

opensearch_instance_type = "t3.small.search"
opensearch_volume_size   = 20

object_lock_days = 7
