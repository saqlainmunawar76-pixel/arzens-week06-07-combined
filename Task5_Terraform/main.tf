# =============================================================================
# THE ARZENS — Week 07 Task 5: Secure Cloud Infrastructure
# Root module: wires vpc -> security -> compute -> storage together.
# =============================================================================

module "vpc" {
  source = "./modules/vpc"

  project_name             = var.project_name
  vpc_cidr                 = var.vpc_cidr
  public_subnet_cidr       = var.public_subnet_cidr
  availability_zone        = var.availability_zone
  flow_log_retention_days  = var.flow_log_retention_days
  kms_key_arn              = var.kms_key_arn
  tags                     = local.common_tags
}

module "security" {
  source = "./modules/security"

  project_name      = var.project_name
  vpc_id            = module.vpc.vpc_id
  subnet_id         = module.vpc.public_subnet_id
  admin_cidr_blocks = var.admin_cidr_blocks
  tags              = local.common_tags
}

module "compute" {
  source = "./modules/compute"

  project_name        = var.project_name
  instance_type       = var.instance_type
  subnet_id           = module.vpc.public_subnet_id
  security_group_id   = module.security.security_group_id
  key_pair_name       = var.key_pair_name
  root_volume_size_gb = var.root_volume_size_gb
  kms_key_arn         = var.kms_key_arn
  tags                = local.common_tags
}

module "storage" {
  source = "./modules/storage"

  bucket_name                         = "${var.project_name}-${var.bucket_suffix}"
  kms_key_arn                         = var.kms_key_arn
  noncurrent_version_expiration_days  = var.s3_noncurrent_version_expiration_days
  tags                                = local.common_tags
}

locals {
  common_tags = merge(var.tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}
