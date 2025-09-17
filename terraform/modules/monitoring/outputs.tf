output "dashboard_url" {
  description = "CloudWatch Dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "application_log_group_name" {
  description = "Application log group name"
  value       = aws_cloudwatch_log_group.application_logs.name
}

output "filtered_log_group_name" {
  description = "Filtered log group name"
  value       = aws_cloudwatch_log_group.filtered_logs.name
}

output "pii_filter_lambda_arn" {
  description = "PII filter Lambda function ARN"
  value       = aws_lambda_function.pii_filter.arn
}

output "alarm_names" {
  description = "List of CloudWatch alarm names"
  value = [
    aws_cloudwatch_metric_alarm.high_cpu_utilization.alarm_name,
    aws_cloudwatch_metric_alarm.rds_replica_lag.alarm_name,
    aws_cloudwatch_metric_alarm.high_error_rate.alarm_name,
    aws_cloudwatch_metric_alarm.high_response_time.alarm_name,
    aws_cloudwatch_metric_alarm.http_5xx_error_rate.alarm_name
  ]
}
