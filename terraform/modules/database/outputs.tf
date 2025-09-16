output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
}

output "rds_port" {
  description = "RDS instance port"
  value       = aws_db_instance.main.port
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "redis_port" {
  description = "ElastiCache Redis port"
  value       = aws_elasticache_replication_group.main.port
}

output "database_name" {
  description = "Database name"
  value       = aws_db_instance.main.db_name
}

output "database_username" {
  description = "Database master username"
  value       = aws_db_instance.main.username
}

output "assets_bucket_name" {
  description = "Assets S3 bucket name"
  value       = aws_s3_bucket.assets.bucket
}

output "terraform_state_bucket_name" {
  description = "Terraform state S3 bucket name"
  value       = aws_s3_bucket.terraform_state.bucket
}

output "dynamodb_table_name" {
  description = "DynamoDB table for Terraform locks"
  value       = aws_dynamodb_table.terraform_locks.name
}

output "rds_instance_id" {
  description = "RDS instance identifier"
  value       = aws_db_instance.main.identifier
}

