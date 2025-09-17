#!/usr/bin/env python3
"""
AWS Cost Optimization Analysis
Analyzes infrastructure costs and provides optimization recommendations
"""

import boto3
import json
from datetime import datetime, timedelta
from collections import defaultdict

class CostOptimizationAnalyzer:
    def __init__(self, region='us-east-1'):
        self.region = region
        self.ce = boto3.client('ce', region_name='us-east-1')  # Cost Explorer is only in us-east-1
        self.ec2 = boto3.client('ec2', region_name=region)
        self.rds = boto3.client('rds', region_name=region)
        self.elasticache = boto3.client('elasticache', region_name=region)
        
    def get_cost_data(self, days=30):
        """Get cost data for the last N days"""
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        try:
            response = self.ce.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='DAILY',
                Metrics=['BlendedCost'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                ]
            )
            
            return response['ResultsByTime']
        except Exception as e:
            print(f"Error fetching cost data: {e}")
            return []
    
    def analyze_ec2_usage(self):
        """Analyze EC2 instances for optimization opportunities"""
        
        optimizations = []
        
        try:
            # Get all running instances
            instances = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_type = instance['InstanceType']
                    launch_time = instance['LaunchTime']
                    
                    # Calculate uptime
                    uptime_days = (datetime.now(launch_time.tzinfo) - launch_time).days
                    
                    # Check for optimization opportunities
                    if uptime_days > 30:  # Long-running instance
                        optimizations.append({
                            'type': 'Reserved Instance',
                            'resource': instance_id,
                            'instance_type': instance_type,
                            'recommendation': f'Consider Reserved Instance for {instance_type}',
                            'potential_savings': self.calculate_ri_savings(instance_type),
                            'uptime_days': uptime_days
                        })
                    
                    # Check for right-sizing opportunities
                    if self.is_oversized(instance_type):
                        optimizations.append({
                            'type': 'Right-sizing',
                            'resource': instance_id,
                            'instance_type': instance_type,
                            'recommendation': f'Consider downsizing {instance_type}',
                            'potential_savings': self.calculate_rightsizing_savings(instance_type),
                            'reason': 'Instance appears oversized for workload'
                        })
                        
        except Exception as e:
            print(f"Error analyzing EC2: {e}")
            
        return optimizations
    
    def analyze_rds_usage(self):
        """Analyze RDS instances for optimization opportunities"""
        
        optimizations = []
        
        try:
            db_instances = self.rds.describe_db_instances()
            
            for db in db_instances['DBInstances']:
                db_id = db['DBInstanceIdentifier']
                db_class = db['DBInstanceClass']
                engine = db['Engine']
                
                # Check for Reserved Instance opportunity
                optimizations.append({
                    'type': 'RDS Reserved Instance',
                    'resource': db_id,
                    'instance_class': db_class,
                    'engine': engine,
                    'recommendation': f'Consider Reserved Instance for {db_class}',
                    'potential_savings': '20-40% cost reduction',
                    'commitment': '1-3 years'
                })
                
                # Check for storage optimization
                if db.get('StorageType') == 'gp2':
                    optimizations.append({
                        'type': 'Storage Optimization',
                        'resource': db_id,
                        'recommendation': 'Consider upgrading to gp3 storage',
                        'potential_savings': 'Up to 20% storage cost reduction',
                        'benefit': 'Better performance and cost efficiency'
                    })
                        
        except Exception as e:
            print(f"Error analyzing RDS: {e}")
            
        return optimizations
    
    def analyze_s3_usage(self):
        """Analyze S3 usage for optimization opportunities"""
        
        optimizations = []
        
        try:
            s3 = boto3.client('s3', region_name=self.region)
            buckets = s3.list_buckets()
            
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                
                # Check for lifecycle policies
                try:
                    s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                except s3.exceptions.NoSuchLifecycleConfiguration:
                    optimizations.append({
                        'type': 'S3 Lifecycle Policy',
                        'resource': bucket_name,
                        'recommendation': 'Implement S3 lifecycle policies',
                        'potential_savings': '30-50% storage costs',
                        'actions': [
                            'Transition to Standard-IA after 30 days',
                            'Transition to Glacier after 90 days',
                            'Delete incomplete multipart uploads'
                        ]
                    })
                
                # Check for intelligent tiering
                optimizations.append({
                    'type': 'S3 Intelligent Tiering',
                    'resource': bucket_name,
                    'recommendation': 'Enable S3 Intelligent Tiering',
                    'potential_savings': 'Automatic cost optimization',
                    'benefit': 'Automatic movement between access tiers'
                })
                        
        except Exception as e:
            print(f"Error analyzing S3: {e}")
            
        return optimizations
    
    def calculate_ri_savings(self, instance_type):
        """Calculate potential Reserved Instance savings"""
        
        # Simplified calculation based on common RI discounts
        savings_mapping = {
            't3.micro': {'1year': '$50-100', '3year': '$100-200'},
            't3.small': {'1year': '$100-200', '3year': '$200-400'},
            't3.medium': {'1year': '$200-400', '3year': '$400-800'},
            't3.large': {'1year': '$400-700', '3year': '$700-1200'},
            'm5.large': {'1year': '$500-800', '3year': '$900-1500'},
            'm5.xlarge': {'1year': '$1000-1500', '3year': '$1800-2500'}
        }
        
        return savings_mapping.get(instance_type, {'1year': '20-40%', '3year': '40-60%'})
    
    def calculate_rightsizing_savings(self, instance_type):
        """Calculate potential right-sizing savings"""
        
        # Simplified right-sizing savings
        return '15-30% monthly cost reduction'
    
    def is_oversized(self, instance_type):
        """Check if instance type appears oversized"""
        
        # Simplified check based on instance type
        oversized_patterns = ['xlarge', '2xlarge', '4xlarge']
        return any(pattern in instance_type for pattern in oversized_patterns)
    
    def generate_report(self):
        """Generate comprehensive cost optimization report"""
        
        print("🔍 Analyzing AWS infrastructure costs...")
        
        # Get cost data
        cost_data = self.get_cost_data(30)
        
        # Analyze resources
        ec2_optimizations = self.analyze_ec2_usage()
        rds_optimizations = self.analyze_rds_usage()
        s3_optimizations = self.analyze_s3_usage()
        
        # Generate report
        report = {
            'analysis_date': datetime.now().isoformat(),
            'cost_analysis_period': '30 days',
            'total_optimizations': len(ec2_optimizations) + len(rds_optimizations) + len(s3_optimizations),
            'optimizations': {
                'ec2': ec2_optimizations,
                'rds': rds_optimizations,
                's3': s3_optimizations
            },
            'summary': self.generate_summary(ec2_optimizations + rds_optimizations + s3_optimizations)
        }
        
        return report
    
    def generate_summary(self, all_optimizations):
        """Generate optimization summary"""
        
        optimization_types = defaultdict(int)
        for opt in all_optimizations:
            optimization_types[opt['type']] += 1
        
        return {
            'total_opportunities': len(all_optimizations),
            'top_opportunities': dict(optimization_types),
            'estimated_monthly_savings': '$200-800',  # Simplified estimate
            'key_recommendations': [
                'Implement Reserved Instances for long-running workloads',
                'Enable S3 lifecycle policies for automated tiering',
                'Consider right-sizing oversized instances',
                'Upgrade RDS storage to gp3 for better cost efficiency'
            ]
        }
    
    def save_report(self, report, filename='cost-optimization-report.json'):
        """Save report to file"""
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"✅ Cost optimization report saved to {filename}")

def main():
    analyzer = CostOptimizationAnalyzer()
    report = analyzer.generate_report()
    analyzer.save_report(report)
    
    # Print summary
    print("\n📊 Cost Optimization Summary")
    print("=" * 50)
    print(f"Total optimization opportunities: {report['total_optimizations']}")
    print(f"Estimated monthly savings: {report['summary']['estimated_monthly_savings']}")
    print("\n🎯 Key Recommendations:")
    for i, rec in enumerate(report['summary']['key_recommendations'], 1):
        print(f"{i}. {rec}")

if __name__ == "__main__":
    main()
