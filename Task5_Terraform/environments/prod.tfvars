# Prod environment overrides — larger instance, longer log retention for compliance.
environment              = "prod"
instance_type            = "t3.small"
flow_log_retention_days  = 365
root_volume_size_gb      = 50
