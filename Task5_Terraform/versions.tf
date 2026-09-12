terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state backend — commented out so `terraform init` works locally
  # out of the box for grading. Uncomment and fill in your own bucket/table
  # to get encrypted remote state + state locking in a real deployment.
  #
  # backend "s3" {
  #   bucket         = "arzens-ti-platform-tfstate"
  #   key            = "week07/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   kms_key_id     = "alias/terraform-state-key"
  #   dynamodb_table = "arzens-ti-platform-tf-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy = "terraform"
      Project   = var.project_name
    }
  }
}
