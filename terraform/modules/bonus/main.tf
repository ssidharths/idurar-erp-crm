# ChatOps Lambda Function
resource "aws_lambda_function" "chatops" {
  filename         = "chatops.zip"
  function_name    = "${var.project_name}-chatops"
  role            = aws_iam_role.chatops_lambda.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 30

  source_code_hash = data.archive_file.chatops_zip.output_base64sha256

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      GEMINI_API_KEY    = var.gemini_api_key
      PROJECT_NAME      = var.project_name
    }
  }

  tags = {
    Name        = "${var.project_name}-chatops"
    Environment = var.environment
  }
}

# ChatOps Lambda deployment package
data "archive_file" "chatops_zip" {
  type        = "zip"
  output_path = "chatops.zip"
  source {
    content = <<EOF
import json
import boto3
import os
import requests
from datetime import datetime
import urllib.parse

def handler(event, context):
    """
    ChatOps Lambda function triggered by SNS
    Uses Gemini to answer infrastructure questions and posts to Slack
    """
    
    print(f"Received event: {json.dumps(event)}")
    
    try:
        # Parse SNS message
        for record in event['Records']:
            if record['EventSource'] == 'aws:sns':
                message = json.loads(record['Sns']['Message'])
                subject = record['Sns'].get('Subject', 'Infrastructure Query')
                
                # Extract question from message or use default
                question = extract_question(message, subject)
                
                print(f"Processing question: {question}")
                
                # Get infrastructure information
                infra_info = get_infrastructure_info()
                
                # Ask Gemini for response
                response = ask_gemini(question, infra_info)
                
                # Post to Slack
                post_to_slack(question, response, subject)
                
    except Exception as e:
        print(f"Error in ChatOps: {str(e)}")
        post_error_to_slack(str(e))
    
    return {
        'statusCode': 200,
        'body': json.dumps('ChatOps processed successfully')
    }

def extract_question(message, subject):
    """Extract question from SNS message"""
    
    # Check if message contains a direct question
    if isinstance(message, dict):
        question = message.get('question', message.get('Message', ''))
    else:
        question = str(message)
    
    # If no specific question, generate one based on subject
    if not question or len(question.strip()) < 10:
        if 'alarm' in subject.lower():
            question = "What infrastructure components are currently experiencing issues?"
        elif 'security' in subject.lower():
            question = "What are the current security findings in our infrastructure?"
        elif 'config' in subject.lower():
            question = "What compliance violations need attention?"
        else:
            question = "Give me a summary of our current AWS infrastructure status"
    
    return question

def get_infrastructure_info():
    """Gather current infrastructure information"""
    
    project_name = os.environ.get('PROJECT_NAME', 'devops-assignment')
    
    # Initialize AWS clients
    ec2 = boto3.client('ec2')
    rds = boto3.client('rds')
    eks = boto3.client('eks')
    cloudwatch = boto3.client('cloudwatch')
    
    infra_info = {
        'timestamp': datetime.now().isoformat(),
        'project': project_name
    }
    
    try:
        # Get VPC information
        vpcs = ec2.describe_vpcs(
            Filters=[{'Name': 'tag:Name', 'Values': [f'{project_name}-vpc']}]
        )
        if vpcs['Vpcs']:
            vpc = vpcs['Vpcs'][0]
            infra_info['vpc'] = {
                'id': vpc['VpcId'],
                'cidr': vpc['CidrBlock'],
                'state': vpc['State']
            }
            
            # Get subnets
            subnets = ec2.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]
            )
            infra_info['subnets'] = {
                'public': [],
                'private': []
            }
            
            for subnet in subnets['Subnets']:
                subnet_info = {
                    'id': subnet['SubnetId'],
                    'cidr': subnet['CidrBlock'],
                    'az': subnet['AvailabilityZone']
                }
                
                # Determine if public or private based on tags
                tags = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                if tags.get('Type') == 'public':
                    infra_info['subnets']['public'].append(subnet_info)
                else:
                    infra_info['subnets']['private'].append(subnet_info)
        
        # Get EKS cluster information
        try:
            clusters = eks.list_clusters()
            for cluster_name in clusters['clusters']:
                if project_name in cluster_name:
                    cluster = eks.describe_cluster(name=cluster_name)
                    infra_info['eks'] = {
                        'name': cluster_name,
                        'status': cluster['cluster']['status'],
                        'version': cluster['cluster']['version'],
                        'endpoint': cluster['cluster']['endpoint']
                    }
                    break
        except Exception as e:
            print(f"Error getting EKS info: {e}")
        
        # Get RDS information
        try:
            db_instances = rds.describe_db_instances()
            infra_info['databases'] = []
            for db in db_instances['DBInstances']:
                if project_name in db['DBInstanceIdentifier']:
                    infra_info['databases'].append({
                        'id': db['DBInstanceIdentifier'],
                        'engine': db['Engine'],
                        'status': db['DBInstanceStatus'],
                        'class': db['DBInstanceClass']
                    })
        except Exception as e:
            print(f"Error getting RDS info: {e}")
        
        # Get recent CloudWatch alarms
        try:
            alarms = cloudwatch.describe_alarms(
                StateValue='ALARM',
                MaxRecords=10
            )
            infra_info['active_alarms'] = []
            for alarm in alarms['MetricAlarms']:
                if project_name in alarm['AlarmName']:
                    infra_info['active_alarms'].append({
                        'name': alarm['AlarmName'],
                        'state': alarm['StateValue'],
                        'reason': alarm['StateReason']
                    })
        except Exception as e:
            print(f"Error getting CloudWatch alarms: {e}")
            
    except Exception as e:
        print(f"Error gathering infrastructure info: {str(e)}")
        infra_info['error'] = str(e)
    
    return infra_info

def ask_gemini(question, infra_info):
    """Ask Google Gemini for infrastructure insights"""
    
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key or api_key == 'fallback':
        return generate_fallback_response(question, infra_info)
    
    prompt = f"""
    You are an AWS infrastructure expert providing ChatOps support. 
    A team member has asked: "{question}"
    
    Here's the current infrastructure information:
    {json.dumps(infra_info, indent=2)}
    
    Please provide a concise, actionable response that:
    1. Answers the specific question
    2. Highlights any issues or concerns
    3. Provides specific recommendations
    4. Uses emojis to make it Slack-friendly
    5. Keeps the response under 500 words
    
    Focus on practical, immediate insights the team can act on.
    """
    
    try:
        response = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {api_key}'
            },
            json={
                'contents': [{
                    'parts': [{'text': prompt}]
                }],
                'generationConfig': {
                    'temperature': 0.3,
                    'topK': 40,
                    'topP': 0.95,
                    'maxOutputTokens': 1024
                }
            },
            timeout=15
        )
        
        if response.status_code == 200:
            result = response.json()
            if 'candidates' in result and len(result['candidates']) > 0:
                return result['candidates'][0]['content']['parts'][0]['text']
        
        print(f"Gemini API error: {response.status_code} - {response.text}")
        return generate_fallback_response(question, infra_info)
        
    except Exception as e:
        print(f"Error calling Gemini: {e}")
        return generate_fallback_response(question, infra_info)

def generate_fallback_response(question, infra_info):
    """Generate a fallback response when Gemini is unavailable"""
    
    response_parts = ["🤖 *Infrastructure Status Report*\n"]
    
    # VPC info
    if 'vpc' in infra_info:
        vpc = infra_info['vpc']
        response_parts.append(f"🌐 *VPC*: {vpc['id']} ({vpc['cidr']}) - {vpc['state']}")
    
    # Subnet info
    if 'subnets' in infra_info:
        subnets = infra_info['subnets']
        response_parts.append(f"📡 *Subnets*: {len(subnets['public'])} public, {len(subnets['private'])} private")
    
    # EKS info
    if 'eks' in infra_info:
        eks = infra_info['eks']
        response_parts.append(f"⚙️ *EKS Cluster*: {eks['name']} (v{eks['version']}) - {eks['status']}")
    
    # Database info
    if 'databases' in infra_info and infra_info['databases']:
        db_count = len(infra_info['databases'])
        response_parts.append(f"🗃️ *Databases*: {db_count} RDS instances running")
    
    # Alarms info
    if 'active_alarms' in infra_info:
        alarm_count = len(infra_info['active_alarms'])
        if alarm_count > 0:
            response_parts.append(f"🚨 *Active Alarms*: {alarm_count} alarms need attention")
            for alarm in infra_info['active_alarms'][:3]:  # Show first 3
                response_parts.append(f"  • {alarm['name']}: {alarm['reason']}")
        else:
            response_parts.append("✅ *Monitoring*: All alarms in OK state")
    
    # Answer specific questions
    question_lower = question.lower()
    if 'subnet' in question_lower:
        if 'subnets' in infra_info:
            response_parts.append(f"\n📋 *Subnet Details*:")
            for subnet in infra_info['subnets']['public'][:2]:
                response_parts.append(f"  • Public: {subnet['id']} ({subnet['cidr']}) in {subnet['az']}")
            for subnet in infra_info['subnets']['private'][:2]:
                response_parts.append(f"  • Private: {subnet['id']} ({subnet['cidr']}) in {subnet['az']}")
    
    response_parts.append(f"\n⏰ *Report generated*: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    
    return "\n".join(response_parts)

def post_to_slack(question, response, subject):
    """Post ChatOps response to Slack"""
    
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    if not webhook_url:
        print("No Slack webhook URL configured")
        return
    
    payload = {
        "text": f"🤖 *ChatOps Response*",
        "attachments": [
            {
                "color": "good",
                "fields": [
                    {
                        "title": "❓ Question",
                        "value": question,
                        "short": False
                    },
                    {
                        "title": "💡 Response",
                        "value": response,
                        "short": False
                    }
                ],
                "footer": "AWS ChatOps powered by Gemini AI",
                "ts": int(datetime.now().timestamp())
            }
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 200:
            print("Successfully posted to Slack")
        else:
            print(f"Failed to post to Slack: {response.status_code}")
    except Exception as e:
        print(f"Error posting to Slack: {str(e)}")

def post_error_to_slack(error_message):
    """Post error message to Slack"""
    
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    if not webhook_url:
        return
    
    payload = {
        "text": "🚨 *ChatOps Error*",
        "attachments": [
            {
                "color": "danger",
                "fields": [
                    {
                        "title": "Error",
                        "value": error_message,
                        "short": False
                    }
                ],
                "footer": "AWS ChatOps Error Handler"
            }
        ]
    }
    
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        print(f"Failed to post error to Slack: {e}")
EOF
    filename = "index.py"
  }
}

# IAM role for ChatOps Lambda
resource "aws_iam_role" "chatops_lambda" {
  name = "${var.project_name}-chatops-lambda-role"

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
    Name        = "${var.project_name}-chatops-lambda-role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "chatops_lambda_policy" {
  name = "${var.project_name}-chatops-lambda-policy"
  role = aws_iam_role.chatops_lambda.id

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
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "rds:DescribeDBInstances",
          "eks:ListClusters",
          "eks:DescribeCluster",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:GetMetricStatistics"
        ]
        Resource = "*"
      }
    ]
  })
}

# SNS subscription to trigger ChatOps Lambda
resource "aws_sns_topic_subscription" "chatops" {
  topic_arn = var.sns_topic_arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.chatops.arn
}

# Permission for SNS to invoke Lambda
resource "aws_lambda_permission" "allow_sns_chatops" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.chatops.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = var.sns_topic_arn
}

# Test Lambda function for manual ChatOps testing
resource "aws_lambda_function" "chatops_test" {
  filename         = "chatops_test.zip"
  function_name    = "${var.project_name}-chatops-test"
  role            = aws_iam_role.chatops_lambda.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 10

  source_code_hash = data.archive_file.chatops_test_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = var.sns_topic_arn
    }
  }

  tags = {
    Name        = "${var.project_name}-chatops-test"
    Environment = var.environment
  }
}

# ChatOps test function deployment package
data "archive_file" "chatops_test_zip" {
  type        = "zip"
  output_path = "chatops_test.zip"
  source {
    content = <<EOF
import json
import boto3

def handler(event, context):
    """
    Test function to manually trigger ChatOps
    """
    
    # Parse the test question from event
    question = event.get('question', 'Give me a summary of our AWS infrastructure')
    
    # Publish to SNS to trigger ChatOps
    sns = boto3.client('sns')
    
    message = {
        'question': question,
        'source': 'manual-test',
        'timestamp': context.aws_request_id
    }
    
    response = sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Message=json.dumps(message),
        Subject=f'ChatOps Test: {question[:50]}...'
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'ChatOps test triggered successfully',
            'question': question,
            'sns_message_id': response['MessageId']
        })
    }
EOF
    filename = "index.py"
  }
}
