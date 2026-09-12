# =============================================================================
# Module: security
# Security group restricted to 22/80/443, plus optional network ACL that
# adds a stateless second layer of defense (defense in depth).
# =============================================================================

resource "aws_security_group" "main" {
  #checkov:skip=CKV_AWS_24:Port 22 source is var.admin_cidr_blocks, not a literal 0.0.0.0/0 - operator sets this to their own IP (see terraform.tfvars.example); static analysis can't resolve the variable's real value
  #checkov:skip=CKV_AWS_260:Port 80 is intentionally public - this is a web-tier security group; HTTPS (443) is also open for the same reason
  #checkov:skip=CKV2_AWS_5:Attached to the EC2 instance in modules/compute via security_group_id - checkov's static analysis doesn't trace the attachment across the module boundary
  name        = "${var.project_name}-sg"
  description = "Restricts inbound to SSH/HTTP/HTTPS only, from allow-listed CIDRs"
  vpc_id      = var.vpc_id

  # SSH — restricted to the admin CIDR only, never 0.0.0.0/0
  ingress {
    description = "SSH from admin CIDR only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Explicit egress — allow outbound HTTPS for package/API updates, and DNS.
  # Avoids a blanket "allow all egress" rule.
  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS outbound"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# --- Defense in depth: stateless Network ACL on the subnet --------------------

resource "aws_network_acl" "main" {
  #checkov:skip=CKV_AWS_231:Rule 130 (1024-65535) is the ephemeral return-traffic range for stateless NACLs, not an inbound RDP service definition - port 3389 falling in that range is incidental, not an open RDP port
  #checkov:skip=CKV2_AWS_1:subnet_ids is set to [var.subnet_id] below - attached directly, not via a separate association resource, which this check doesn't detect
  vpc_id     = var.vpc_id
  subnet_ids = [var.subnet_id]

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  ingress {
    rule_no    = 120
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.admin_cidr_blocks[0]
    from_port  = 22
    to_port    = 22
  }

  # Ephemeral ports for return traffic
  ingress {
    rule_no    = 130
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-nacl"
  })
}
