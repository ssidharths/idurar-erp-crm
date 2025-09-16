# RDS Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "${var.project_name}-db-subnet-group"
  }
}

# RDS Parameter Group
resource "aws_db_parameter_group" "main" {
  family = "postgres15"
  name   = "${var.project_name}-db-params"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "all"
  }

  tags = {
    Name = "${var.project_name}-db-params"
  }
}

# Generate random password for RDS
resource "random_password" "rds_password" {
  length  = 16
  special = true
}

# Store RDS password in SSM Parameter Store
resource "aws_ssm_parameter" "rds_password" {
  name        = "/${var.project_name}/database/password"
  description = "RDS master password"
  type        = "SecureString"
  value       = random_password.rds_password.result
  key_id      = var.kms_key_arn

  tags = {
    Name = "${var.project_name}-rds-password"
  }
}

# RDS PostgreSQL Instance
resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-database"

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp2"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"

  db_name  = "appdb"
  username = "dbadmin"
  password = random_password.rds_password.result

  vpc_security_group_ids = [var.rds_security_group_id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  parameter_group_name   = aws_db_parameter_group.main.name

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  multi_az                 = true
  publicly_accessible      = false
  skip_final_snapshot      = true
  delete_automated_backups = true

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = {
    Name = "${var.project_name}-database"
  }
}

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.project_name}-cache-subnet"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "${var.project_name}-cache-subnet"
  }
}

# ElastiCache Parameter Group
resource "aws_elasticache_parameter_group" "main" {
  family = "redis7.x"
  name   = "${var.project_name}-cache-params"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  tags = {
    Name = "${var.project_name}-cache-params"
  }
}

# ElastiCache Redis Cluster
resource "aws_elasticache_replication_group" "main" {
  replication_group_id = "${var.project_name}-redis"
  description          = "Redis cluster for ${var.project_name}"

  node_type            = "cache.t3.micro"
  port                 = 6379
  parameter_group_name = aws_elasticache_parameter_group.main.name

  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [var.redis_security_group_id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = var.kms_key_arn

  engine_version = "7.0"

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }

  tags = {
    Name = "${var.project_name}-redis"
  }
}

# CloudWatch Log Group for Redis
resource "aws_cloudwatch_log_group" "redis_slow" {
  name              = "/aws/elasticache/${var.project_name}/slow-log"
  retention_in_days = 7
  kms_key_id        = var.kms_key_arn

  tags = {
    Name = "${var.project_name}-redis-logs"
  }
}

# S3 Bucket for static assets
resource "aws_s3_bucket" "assets" {
  bucket = "${var.project_name}-assets-${random_string.bucket_suffix.result}"

  tags = {
    Name = "${var.project_name}-assets"
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }

}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket for Terraform state
resource "aws_s3_bucket" "terraform_state" {
  bucket = "${var.project_name}-tfstate-${random_string.bucket_suffix.result}"

  tags = {
    Name = "${var.project_name}-terraform-state"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# DynamoDB table for Terraform state locking
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "${var.project_name}-tfstate-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = {
    Name = "${var.project_name}-tfstate-locks"
  }
}
