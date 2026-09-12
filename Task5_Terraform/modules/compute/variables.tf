variable "project_name" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "subnet_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "key_pair_name" {
  description = "Name of an existing EC2 key pair (never generate/commit private keys via Terraform)"
  type        = string
}

variable "root_volume_size_gb" {
  type    = number
  default = 20
}

variable "kms_key_arn" {
  type    = string
  default = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
