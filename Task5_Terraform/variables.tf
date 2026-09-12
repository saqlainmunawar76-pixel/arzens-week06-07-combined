variable "project_name" {
  description = "Name prefix used across all resources"
  type        = string
  default     = "arzens-ti-platform"
}

variable "environment" {
  description = "Deployment environment (dev/staging/prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.0.1.0/24"
}

variable "availability_zone" {
  type    = string
  default = "us-east-1a"
}

variable "flow_log_retention_days" {
  type    = number
  default = 365
}

variable "admin_cidr_blocks" {
  description = "CIDR(s) allowed to SSH into the instance. Set this to your own IP/32 — never leave as 0.0.0.0/0."
  type        = list(string)
  # Intentionally no default — forces the operator to set this explicitly
  # in terraform.tfvars rather than silently opening SSH to the world.
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "key_pair_name" {
  description = "Existing AWS EC2 key pair name for SSH access"
  type        = string
}

variable "root_volume_size_gb" {
  type    = number
  default = 20
}

variable "kms_key_arn" {
  description = "KMS key ARN for encrypting EBS/S3. Leave null to use the AWS-managed default key."
  type        = string
  default     = null
}

variable "bucket_suffix" {
  description = "Suffix appended to the S3 bucket name (bucket names must be globally unique)"
  type        = string
}

variable "s3_noncurrent_version_expiration_days" {
  type    = number
  default = 90
}

variable "tags" {
  description = "Additional tags merged into every resource"
  type        = map(string)
  default     = {}
}
