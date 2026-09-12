variable "bucket_name" {
  type = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for SSE-KMS encryption. Use 'aws:kms' with the account's default key if a custom CMK isn't provisioned."
  type        = string
  default     = null
}

variable "noncurrent_version_expiration_days" {
  type    = number
  default = 90
}

variable "tags" {
  type    = map(string)
  default = {}
}
