output "vpc_id" {
  description = "ID of the created VPC"
  value       = module.vpc.vpc_id
}

output "public_subnet_id" {
  value = module.vpc.public_subnet_id
}

output "security_group_id" {
  value = module.security.security_group_id
}

output "instance_id" {
  value = module.compute.instance_id
}

output "instance_private_ip" {
  value = module.compute.private_ip
}

output "s3_bucket_name" {
  value = module.storage.bucket_id
}

output "s3_bucket_arn" {
  value = module.storage.bucket_arn
}
