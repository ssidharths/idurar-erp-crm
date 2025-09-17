output "vpc_id" {
  description = "ID of the VPC"
  value       = module.networking.vpc_id
}

output "eks_cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.compute.cluster_endpoint
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.compute.cluster_name
}

output "ecr_repository_url" {
  description = "URL of the ECR repository"
  value       = module.compute.ecr_repository_url
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = module.database.rds_endpoint
}

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = module.database.redis_endpoint
}

output "assets_bucket_name" {
  description = "Assets S3 bucket name"
  value       = module.database.assets_bucket_name
}

output "dashboard_url" {
  description = "CloudWatch Dashboard URL"
  value       = module.monitoring.dashboard_url
}

output "monitoring_alarm_names" {
  description = "List of monitoring alarm names"
  value       = module.monitoring.alarm_names
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = module.security.sns_topic_arn
}
