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

variable "finding_publishing_frequency" {
  description = "GuardDuty finding publishing frequency"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "enable_s3_protection" {
  description = "Enable S3 protection in GuardDuty"
  type        = bool
  default     = true
}

variable "enable_kubernetes_protection" {
  description = "Enable Kubernetes protection in GuardDuty"
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  description = "Enable malware protection in GuardDuty"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email for security notification (GuardDuty, config)"
  type        = string
  default     = "devt.mailbox@gmail.com"
}

variable "sns_topic_arn" {
  description = "SNS Topic ARN for ChatOps notifications"
  type        = string
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for ChatOps notifications"
  type        = string
}

variable "gemini_api_key" {
  description = "Google Gemini AI API Key"
  type        = string
  sensitive   = true
}
