# =============================================================================
# Module: compute
# EC2 instance hardened per assignment spec: key-pair auth, no root login,
# latest AMI via SSM parameter, IMDSv2 enforced, encrypted root volume.
# =============================================================================

# Always resolve the latest patched Amazon Linux 2023 AMI at apply time
# rather than hardcoding an AMI ID that goes stale.
data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# =============================================================================
# Module: compute
# EC2 instance hardened per assignment spec: key-pair auth, no root login,
# latest AMI via SSM parameter, IMDSv2 enforced, encrypted root volume,
# EBS-optimized, with a least-privilege IAM instance role (SSM only — no
# broad admin access) instead of no role at all.
# =============================================================================

# Always resolve the latest patched Amazon Linux 2023 AMI at apply time
# rather than hardcoding an AMI ID that goes stale.
data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# --- Least-privilege IAM role for the instance ---------------------------------
# Grants only SSM Session Manager access (for break-glass shell access without
# opening SSH more broadly) — no S3, no EC2, no broad admin permissions.
resource "aws_iam_role" "instance_role" {
  name = "${var.project_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.instance_role.name
}

resource "aws_instance" "main" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  key_name               = var.key_pair_name
  iam_instance_profile   = aws_iam_instance_profile.instance_profile.name
  ebs_optimized          = true

  # Enforce IMDSv2 — mitigates SSRF-to-credential-theft attack path.
  metadata_options {
    http_tokens                 = "required"
    http_endpoint                = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = var.root_volume_size_gb
    volume_type           = "gp3"
    encrypted              = true
    kms_key_id            = var.kms_key_arn
    delete_on_termination = true
  }

  # Bootstrap: disable root SSH login and password auth at first boot,
  # in addition to whatever Ansible does post-provisioning (Task 6).
  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
  EOF

  monitoring = true # detailed CloudWatch monitoring

  tags = merge(var.tags, {
    Name = "${var.project_name}-ec2"
  })

  lifecycle {
    ignore_changes = [ami] # avoid forced replacement when the SSM AMI param rolls
  }
}
