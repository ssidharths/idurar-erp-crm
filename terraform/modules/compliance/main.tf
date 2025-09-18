# Enable GuardDuty detector (basic configuration only)
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency

  tags = {
    Name        = "${var.project_name}-guardduty"
    Environment = var.environment
  }
}

# Enable S3 protection feature separately
resource "aws_guardduty_detector_feature" "s3_data_events" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = var.enable_s3_protection ? "ENABLED" : "DISABLED"
}

# Enable EKS audit logs protection feature separately
resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_AUDIT_LOGS"
  status      = var.enable_kubernetes_protection ? "ENABLED" : "DISABLED"
}

# Enable EBS malware protection feature separately
resource "aws_guardduty_detector_feature" "ebs_malware_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = var.enable_malware_protection ? "ENABLED" : "DISABLED"
}

# Enable RDS login events protection feature separately
resource "aws_guardduty_detector_feature" "rds_login_events" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

# Enable EKS runtime monitoring feature separately
resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"
}

# Enable Lambda network logs feature separately
resource "aws_guardduty_detector_feature" "lambda_network_logs" {
  detector_id = aws_guardduty_detector.main.id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

# GuardDuty findings destination (S3 bucket)
resource "aws_s3_bucket" "guardduty_findings" {
  bucket = "${var.project_name}-guardduty-findings-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "${var.project_name}-guardduty-findings"
    Environment = var.environment
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket_versioning" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.guardduty.arn
        sse_algorithm     = "aws:kms"
      }
    }
}

resource "aws_s3_bucket_public_access_block" "guardduty_findings" {
  bucket = aws_s3_bucket.guardduty_findings.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS key for GuardDuty encryption
resource "aws_kms_key" "guardduty" {
  description             = "KMS key for GuardDuty findings encryption"
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow GuardDuty to use the key"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-guardduty-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "guardduty" {
  name          = "alias/${var.project_name}-guardduty-key"
  target_key_id = aws_kms_key.guardduty.key_id
}

# GuardDuty publishing destination
resource "aws_guardduty_publishing_destination" "main" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = aws_s3_bucket.guardduty_findings.arn
  kms_key_arn     = aws_kms_key.guardduty.arn

  depends_on = [aws_s3_bucket_policy.guardduty_findings_policy]
}

# S3 bucket policy for GuardDuty
resource "aws_s3_bucket_policy" "guardduty_findings_policy" {
  bucket = aws_s3_bucket.guardduty_findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Allow GuardDuty to put objects"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.guardduty_findings.arn}/*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "Allow GuardDuty to get bucket location"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:GetBucketLocation"
        Resource = aws_s3_bucket.guardduty_findings.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

data "aws_caller_identity" "current" {}

# AWS Config Configuration Recorder
resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# AWS Config Delivery Channel
resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config.bucket
}

# S3 bucket for Config
resource "aws_s3_bucket" "config" {
  bucket = "${var.project_name}-config-${random_string.config_bucket_suffix.result}"

  tags = {
    Name        = "${var.project_name}-config"
    Environment = var.environment
  }
}

resource "random_string" "config_bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.config.arn
        sse_algorithm     = "aws:kms"
      }
    }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS key for Config
resource "aws_kms_key" "config" {
  description             = "KMS key for AWS Config"
  deletion_window_in_days = 7

  tags = {
    Name        = "${var.project_name}-config-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "config" {
  name          = "alias/${var.project_name}-config-key"
  target_key_id = aws_kms_key.config.key_id
}

# IAM role for Config
resource "aws_iam_role" "config" {
  name = "${var.project_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-config-role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "${var.project_name}-config-s3-policy"
  role = aws_iam_role.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.config.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.config.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# AWS Config Rules

# 1. Check for security groups with unrestricted access
resource "aws_config_config_rule" "security_group_unrestricted_access" {
  name = "${var.project_name}-sg-unrestricted-access"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = {
    Name        = "${var.project_name}-sg-ssh-restricted"
    Environment = var.environment
  }
}

# 2. Check for unencrypted S3 buckets
resource "aws_config_config_rule" "s3_bucket_encryption" {
  name = "${var.project_name}-s3-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = {
    Name        = "${var.project_name}-s3-encryption"
    Environment = var.environment
  }
}

# 3. Check for unencrypted RDS instances
resource "aws_config_config_rule" "rds_encryption" {
  name = "${var.project_name}-rds-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder.main]

  tags = {
    Name        = "${var.project_name}-rds-encryption"
    Environment = var.environment
  }
}

# resource "aws_config_config_rule" "iam_root_access_key_check" {
#   name = "${var.project_name}-iam-root-access-key-check"

#   source {
#     owner             = "AWS"
#     source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
#   }

#   depends_on = [aws_config_configuration_recorder.main]

#   tags = {
#     Name        = "${var.project_name}-iam-root-access-key"
#     Environment = var.environment
#   }
# }
# SNS topic for Config compliance notifications
resource "aws_sns_topic" "config_compliance" {
  name = "${var.project_name}-config-compliance"

  tags = {
    Name        = "${var.project_name}-config-compliance"
    Environment = var.environment
  }
}

resource "aws_sns_topic_subscription" "config_compliance_email" {
  topic_arn = aws_sns_topic.config_compliance.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# EventBridge rule for Config compliance changes
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name        = "${var.project_name}-config-compliance"
  description = "Trigger on Config compliance changes"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType = ["ComplianceChangeNotification"]
    }
  })

  tags = {
    Name        = "${var.project_name}-config-compliance"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "config_compliance_sns" {
  rule      = aws_cloudwatch_event_rule.config_compliance.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.config_compliance.arn
}

# EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project_name}-guardduty-findings"
  description = "Trigger on GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [4.0, 7.0, 8.5, 10.0]  # Medium to Critical severity
    }
  })

  tags = {
    Name        = "${var.project_name}-guardduty-findings"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "guardduty_findings_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.config_compliance.arn
}

# Lambda function for automated remediation
resource "aws_lambda_function" "security_remediation" {
  filename         = "security_remediation.zip"
  function_name    = "${var.project_name}-security-remediation"
  role            = aws_iam_role.remediation_lambda.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 60

  source_code_hash = data.archive_file.remediation_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.config_compliance.arn
    }
  }

  tags = {
    Name        = "${var.project_name}-security-remediation"
    Environment = var.environment
  }
}

# Lambda deployment package for security remediation
data "archive_file" "remediation_zip" {
  type        = "zip"
  output_path = "security_remediation.zip"
  source {
    content = <<EOF
import json
import boto3
import os
from datetime import datetime

def handler(event, context):
    """
    Automated security remediation function
    Responds to Config rule violations and GuardDuty findings
    """
    
    print(f"Received event: {json.dumps(event)}")
    
    # Initialize AWS clients
    ec2 = boto3.client('ec2')
    config = boto3.client('config')
    sns = boto3.client('sns')
    
    try:
        # Process Config compliance changes
        if event.get('source') == 'aws.config':
            handle_config_violation(event, ec2, config, sns)
        
        # Process GuardDuty findings
        elif event.get('source') == 'aws.guardduty':
            handle_guardduty_finding(event, sns)
            
    except Exception as e:
        print(f"Error processing security event: {str(e)}")
        send_alert(sns, f"Security remediation failed: {str(e)}")
    
    return {
        'statusCode': 200,
        'body': json.dumps('Security remediation processed')
    }

def handle_config_violation(event, ec2, config, sns):
    """Handle AWS Config rule violations"""
    
    detail = event.get('detail', {})
    rule_name = detail.get('configRuleName', '')
    resource_type = detail.get('resourceType', '')
    resource_id = detail.get('resourceId', '')
    compliance_type = detail.get('newEvaluationResult', {}).get('complianceType', '')
    
    print(f"Config violation - Rule: {rule_name}, Resource: {resource_id}, Compliance: {compliance_type}")
    
    if compliance_type == 'NON_COMPLIANT':
        
        # Handle security group violations
        if 'sg-' in resource_id and 'security-group' in rule_name.lower():
            remediate_security_group(ec2, resource_id, sns)
        
        # Handle other violations with notifications
        else:
            message = f"""
            Security Compliance Alert
            
            Rule: {rule_name}
            Resource: {resource_id} ({resource_type})
            Status: {compliance_type}
            Time: {datetime.now().isoformat()}
            
            Please review and remediate this compliance violation.
            """
            send_alert(sns, message)

def remediate_security_group(ec2, sg_id, sns):
    """Remediate security group with overly permissive rules"""
    
    try:
        # Get security group details
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = response['SecurityGroups']
        
        dangerous_rules = []
        
        # Check for dangerous inbound rules
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    # Check for dangerous ports
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    
                    dangerous_ports = [22, 3389, 3306, 5432, 1433, 6379, 27017]
                    
                    if any(port >= from_port and port <= to_port for port in dangerous_ports):
                        dangerous_rules.append(rule)
        
        if dangerous_rules:
            # Create backup of current rules
            backup_message = f"Security Group {sg_id} backup: {json.dumps(sg['IpPermissions'])}"
            print(backup_message)
            
            # For demonstration, we'll just alert instead of auto-fixing
            # In production, you might want manual approval for changes
            alert_message = f"""
            CRITICAL: Security Group Auto-Remediation Required
            
            Security Group: {sg_id}
            Dangerous Rules Found: {len(dangerous_rules)}
            
            Rules with 0.0.0.0/0 access to sensitive ports detected.
            Manual review and remediation required.
            
            Backup of current rules logged for recovery.
            """
            
            send_alert(sns, alert_message)
            
    except Exception as e:
        print(f"Error remediating security group {sg_id}: {str(e)}")
        send_alert(sns, f"Failed to remediate security group {sg_id}: {str(e)}")

def handle_guardduty_finding(event, sns):
    """Handle GuardDuty security findings"""
    
    detail = event.get('detail', {})
    finding_type = detail.get('type', 'Unknown')
    severity = detail.get('severity', 0)
    title = detail.get('title', 'GuardDuty Finding')
    description = detail.get('description', 'No description')
    
    alert_message = f"""
    GuardDuty Security Alert
    
    Finding: {title}
    Type: {finding_type}
    Severity: {severity}
    
    Description: {description}
    
    Time: {datetime.now().isoformat()}
    
    Please investigate this security finding immediately.
    """
    
    send_alert(sns, alert_message)

def send_alert(sns, message):
    """Send alert to SNS topic"""
    
    try:
        sns.publish(
            TopicArn=os.environ['SNS_TOPIC_ARN'],
            Message=message,
            Subject='Security Alert - Automated Detection'
        )
        print("Alert sent successfully")
    except Exception as e:
        print(f"Failed to send alert: {str(e)}")
EOF
    filename = "index.py"
  }
}

# IAM role for remediation Lambda
resource "aws_iam_role" "remediation_lambda" {
  name = "${var.project_name}-remediation-lambda-role"

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

  tags = {
    Name        = "${var.project_name}-remediation-lambda-role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "remediation_lambda_policy" {
  name = "${var.project_name}-remediation-lambda-policy"
  role = aws_iam_role.remediation_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "config:GetComplianceDetailsByResource",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

# EventBridge targets for Lambda
resource "aws_cloudwatch_event_target" "config_remediation" {
  rule      = aws_cloudwatch_event_rule.config_compliance.name
  target_id = "SecurityRemediation"
  arn       = aws_lambda_function.security_remediation.arn
}

resource "aws_cloudwatch_event_target" "guardduty_remediation" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SecurityRemediation"
  arn       = aws_lambda_function.security_remediation.arn
}

# Lambda permissions for EventBridge
resource "aws_lambda_permission" "allow_eventbridge_config" {
  statement_id  = "AllowExecutionFromEventBridgeConfig"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance.arn
}

resource "aws_lambda_permission" "allow_eventbridge_guardduty" {
  statement_id  = "AllowExecutionFromEventBridgeGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}
