variable "project_name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "admin_cidr_blocks" {
  description = "CIDR(s) allowed to SSH in. Never leave this as 0.0.0.0/0 in production — scope to your office/VPN IP."
  type        = list(string)
}

variable "tags" {
  type    = map(string)
  default = {}
}
