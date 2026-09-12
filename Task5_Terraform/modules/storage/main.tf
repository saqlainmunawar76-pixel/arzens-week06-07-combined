# =============================================================================
# Module: storage
# Private, encrypted, versioned S3 bucket with public-access block and a
# lifecycle policy — used here for storing enrichment results / IOC exports.
# =============================================================================

# =============================================================================
# Module: storage
# Private, encrypted, versioned S3 bucket with public-access block, access
# logging, and a lifecycle policy — used here for storing enrichment
# results / IOC exports.
# =============================================================================

# --- Access-logging target bucket -----------------------------------------------
# A separate bucket receives server access logs for the main bucket (S3 does
# not allow a bucket to log to itself).
resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV2_AWS_62:Log-sink bucket; wiring notifications on the log bucket itself is not needed for this scope
  #checkov:skip=CKV_AWS_18:This IS the access-log destination bucket - logging a log bucket to itself would be circular
  #checkov:skip=CKV_AWS_144:Single-region log sink is sufficient for this internship-scope deployment; cross-region replication is a production-scale concern
  bucket = "${var.bucket_name}-access-logs"

  tags = merge(var.tags, {
    Name    = "${var.bucket_name}-access-logs"
    Purpose = "s3-access-logging-sink"
  })
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-old-access-logs"
    status = "Enabled"
    expiration {
      days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket" "main" {
  #checkov:skip=CKV2_AWS_62:No downstream event consumer (SQS/Lambda) is provisioned in this scope; add a notification target before wiring this
  #checkov:skip=CKV_AWS_144:Single-region storage is sufficient for this internship-scope deployment; cross-region replication is a production-scale concern
  bucket = var.bucket_name

  tags = merge(var.tags, {
    Name = var.bucket_name
  })
}

resource "aws_s3_bucket_logging" "main" {
  bucket        = aws_s3_bucket.main.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "access-logs/"
}

# Explicit public access block — belt-and-braces even though the bucket has
# no public ACL/policy attached.
resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_expiration_days
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # Ensure failed/incomplete multipart uploads don't accumulate storage cost
    # or linger as an unmonitored, potentially recoverable data remnant.
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Deny any non-TLS request — enforced at the bucket policy level.
resource "aws_s3_bucket_policy" "deny_insecure_transport" {
  bucket = aws_s3_bucket.main.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.main.arn,
        "${aws_s3_bucket.main.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
