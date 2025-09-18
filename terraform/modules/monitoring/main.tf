# CloudWatch Log Groups for centralized logging
resource "aws_cloudwatch_log_group" "application_logs" {
  name              = "/aws/eks/${var.eks_cluster_name}/application"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project_name}-app-logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "infrastructure_logs" {
  name              = "/aws/eks/${var.eks_cluster_name}/infrastructure"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project_name}-infra-logs"
    Environment = var.environment
  }
}

# PII Detection and Filtering Lambda Function
resource "aws_iam_role" "pii_filter_lambda_role" {
  name = "${var.project_name}-pii-filter-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "pii_filter_lambda_policy" {
  name = "${var.project_name}-pii-filter-lambda-policy"
  role = aws_iam_role.pii_filter_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "comprehend:DetectPiiEntities",
          "comprehend:ContainsPiiEntities"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "pii_filter_lambda_basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.pii_filter_lambda_role.name
}

# Lambda function for PII filtering
resource "aws_lambda_function" "pii_filter" {
  filename      = "pii_filter.zip"
  function_name = "${var.project_name}-pii-filter"
  role          = aws_iam_role.pii_filter_lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 30

  source_code_hash = data.archive_file.pii_filter_zip.output_base64sha256

  environment {
    variables = {
      FILTERED_LOG_GROUP = aws_cloudwatch_log_group.filtered_logs.name
    }
  }

  tags = {
    Name        = "${var.project_name}-pii-filter"
    Environment = var.environment
  }
}

# Create the Lambda deployment package
data "archive_file" "pii_filter_zip" {
  type        = "zip"
  output_path = "pii_filter.zip"
  source {
    content  = <<EOF
import json
import boto3
import gzip
import base64
import re
import os
from datetime import datetime

def handler(event, context):
    """
    Lambda function to filter PII from CloudWatch logs
    """
    cw_logs = boto3.client('logs')
    
    # Parse the CloudWatch Logs event
    cw_data = event['awslogs']['data']
    compressed_payload = base64.b64decode(cw_data)
    uncompressed_payload = gzip.decompress(compressed_payload)
    log_data = json.loads(uncompressed_payload)
    
    filtered_events = []
    
    for log_event in log_data['logEvents']:
        message = log_event['message']
        timestamp = log_event['timestamp']
        
        # Filter out PII using regex patterns
        filtered_message = filter_pii(message)
        
        if filtered_message != message:
            print(f"PII detected and filtered in log event at {timestamp}")
        
        filtered_events.append({
            'timestamp': timestamp,
            'message': filtered_message
        })
    
    # Send filtered logs to the filtered log group
    try:
        log_stream_name = f"filtered-{datetime.now().strftime('%Y/%m/%d')}/pii-filtered"
        
        # Create log stream if it doesn't exist
        try:
            cw_logs.create_log_stream(
                logGroupName=os.environ['FILTERED_LOG_GROUP'],
                logStreamName=log_stream_name
            )
        except cw_logs.exceptions.ResourceAlreadyExistsException:
            pass
        
        # Put filtered log events
        cw_logs.put_log_events(
            logGroupName=os.environ['FILTERED_LOG_GROUP'],
            logStreamName=log_stream_name,
            logEvents=filtered_events
        )
        
    except Exception as e:
        print(f"Error writing filtered logs: {str(e)}")
    
    return {
        'statusCode': 200,
        'body': json.dumps(f'Processed {len(filtered_events)} log events')
    }

def filter_pii(message):
    """
    Filter common PII patterns from log messages
    """
    # Email addresses
    message = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL-REDACTED]', message)
    
    # Phone numbers (various formats)
    message = re.sub(r'(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', '[PHONE-REDACTED]', message)
    
    # Credit card numbers
    message = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CARD-REDACTED]', message)
    
    # SSN patterns
    message = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN-REDACTED]', message)
    
    # IP addresses (private info in some contexts)
    message = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP-REDACTED]', message)
    
    # Common password patterns in logs
    message = re.sub(r'(password|pwd|pass)[:=]\s*\S+', r'\1=[PASSWORD-REDACTED]', message, flags=re.IGNORECASE)
    
    # API keys and tokens
    message = re.sub(r'(api[_-]?key|token|secret)[:=]\s*[A-Za-z0-9+/=]{20,}', r'\1=[TOKEN-REDACTED]', message, flags=re.IGNORECASE)
    
    return message
EOF
    filename = "index.py"
  }
}

# Filtered logs destination
resource "aws_cloudwatch_log_group" "filtered_logs" {
  name              = "/aws/lambda/${var.project_name}-filtered-logs"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project_name}-filtered-logs"
    Environment = var.environment
  }
}

# CloudWatch Log Subscription Filter
resource "aws_cloudwatch_log_subscription_filter" "pii_filter" {
  name            = "${var.project_name}-pii-filter"
  log_group_name  = aws_cloudwatch_log_group.application_logs.name
  filter_pattern  = "" # Process all log events
  destination_arn = aws_lambda_function.pii_filter.arn
}

# Permission for CloudWatch Logs to invoke Lambda
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pii_filter.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.application_logs.arn}:*"
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["DevOpsAssignment/Application", "RequestCount", "Service", "hello-app"],
            [".", "ResponseTime", ".", "."],
            [".", "ErrorCount", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "Application Metrics"
          period  = 300
          stat    = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/EKS", "cluster_failed_request_count", "ClusterName", var.eks_cluster_name],
            ["AWS/EKS", "cluster_node_count", ".", "."],
            ["AWS/EKS", "cluster_running_pod_count", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "EKS Cluster Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", var.rds_instance_id],
            [".", "DatabaseConnections", ".", "."],
            [".", "ReplicaLag", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "RDS Performance"
          period  = 300
          yAxis = {
            left = {
              min = 0
              max = 100
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        properties = {
          metrics = [
            ["AWS/ElastiCache", "CPUUtilization", "CacheClusterId", var.redis_cluster_id],
            [".", "NetworkBytesIn", ".", "."],
            [".", "NetworkBytesOut", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "Redis Cache Performance"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        properties = {
          metrics = [
            ["AWS/ContainerInsights", "pod_cpu_utilization", "ClusterName", var.eks_cluster_name, "Namespace", "default"],
            [".", "pod_memory_utilization", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "Pod Resource Utilization"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 6
        properties = {
          query  = "SOURCE '${aws_cloudwatch_log_group.application_logs.name}' | fields @timestamp, @message | filter @message like /ERROR/ | sort @timestamp desc | limit 100"
          region = "us-east-1"
          title  = "Recent Application Errors"
          view   = "table"
        }
      }
    ]
  })
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "high_cpu_utilization" {
  alarm_name          = "${var.project_name}-high-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ContainerInsights"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors pod CPU utilization"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]

  dimensions = {
    ClusterName = var.eks_cluster_name
    Namespace   = "default"
  }

  tags = {
    Name        = "${var.project_name}-high-cpu"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_replica_lag" {
  alarm_name          = "${var.project_name}-rds-replica-lag"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ReplicaLag"
  namespace           = "AWS/RDS"
  period              = "60"
  statistic           = "Average"
  threshold           = "100" # 100 milliseconds
  alarm_description   = "This metric monitors RDS replica lag"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    DBInstanceIdentifier = var.rds_instance_id
  }

  tags = {
    Name        = "${var.project_name}-rds-replica-lag"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "${var.project_name}-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ErrorCount"
  namespace           = "DevOpsAssignment/Application"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors application error rate"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    Service = "hello-app"
  }

  tags = {
    Name        = "${var.project_name}-high-error-rate"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "high_response_time" {
  alarm_name          = "${var.project_name}-high-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "ResponseTime"
  namespace           = "DevOpsAssignment/Application"
  period              = "300"
  statistic           = "Average"
  threshold           = "2000" # 2 seconds
  alarm_description   = "This metric monitors application response time"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    Service = "hello-app"
  }

  tags = {
    Name        = "${var.project_name}-high-response-time"
    Environment = var.environment
  }
}

# Custom metric filter for HTTP 5xx errors
resource "aws_cloudwatch_log_metric_filter" "http_5xx_errors" {
  name           = "${var.project_name}-http-5xx-errors"
  log_group_name = aws_cloudwatch_log_group.application_logs.name
  pattern        = "[timestamp, request_id, level=\"ERROR\", message, status_code=5*]"

  metric_transformation {
    name          = "HTTP5xxErrors"
    namespace     = "DevOpsAssignment/Application"
    value         = "1"
    default_value = "0"
  }
}

# Alarm for HTTP 5xx error rate
resource "aws_cloudwatch_metric_alarm" "http_5xx_error_rate" {
  alarm_name          = "${var.project_name}-http-5xx-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HTTP5xxErrors"
  namespace           = "DevOpsAssignment/Application"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5" # More than 5% error rate
  alarm_description   = "This metric monitors HTTP 5xx error rate"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    Service = "hello-app"
  }

  tags = {
    Name        = "${var.project_name}-http-5xx-errors"
    Environment = var.environment
  }
}

# Enable CloudWatch Container Insights for EKS
resource "aws_eks_addon" "cloudwatch_observability" {
  cluster_name = var.eks_cluster_name
  addon_name   = "amazon-cloudwatch-observability"
  #addon_version            = "v1.3.0-eksbuild.1"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  tags = {
    Name        = "${var.project_name}-cloudwatch-addon"
    Environment = var.environment
  }
}
