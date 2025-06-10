#!/usr/bin/env python3
"""
AWS Attack Executor - Executes real AWS attack techniques
This script performs actual AWS API calls and commands for attack simulation
"""

import boto3
import subprocess
import json
import time
import os
import sys
import requests
from datetime import datetime
from typing import Dict, List, Optional
import logging

class AWSAttackExecutor:
    def __init__(self, splunk_hec_url: str = "http://localhost:8088/services/collector", 
                 hec_token: str = "1b0bb9cc-e884-4ae0-b3fa-9062f200b328"):
        self.hec_url = splunk_hec_url
        self.hec_token = hec_token
        self.headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json"
        }
        
        # Create logs directory for local logging
        self.logs_dir = "attack_logs"
        os.makedirs(self.logs_dir, exist_ok=True)
        self.attack_results = []
        
        # REAL AWS CREDENTIALS - FROM PROVIDED FILES
        self.aws_access_key = "AKIA2HVQ5P6FNAE6FOM7"
        self.aws_secret_key = "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"
        self.aws_region = "us-east-1"
        
        # Initialize AWS clients WITH REAL CREDENTIALS
        try:
            self.session = boto3.Session(
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                region_name=self.aws_region
            )
            self.ec2 = self.session.client('ec2')
            self.iam = self.session.client('iam')
            self.s3 = self.session.client('s3')
            self.sts = self.session.client('sts')
            self.cloudtrail = self.session.client('cloudtrail')
            self.logs = self.session.client('logs')
            self.lambda_client = self.session.client('lambda')
            self.rds = self.session.client('rds')
            print("✅ AWS clients initialized successfully WITH REAL CREDENTIALS")
            print(f"🔐 Using AWS Account: 703671926666")
            print(f"🌍 Region: {self.aws_region}")
        except Exception as e:
            print(f"⚠️ AWS client initialization failed: {e}")
            self.session = None
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
    def log_attack_event(self, technique_id: str, technique_name: str, 
                        action: str, result: Dict, severity: str = "HIGH"):
        """Log real AWS attack execution results to Splunk and local files"""
        event_data = {
            "time": int(time.time()),
            "sourcetype": "aws_attack_execution",
            "source": "aws_attack_executor",
            "event": {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "aws_action": action,
                "execution_result": result,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "attack_type": "REAL_AWS_EXECUTION",
                "aws_region": os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
                "user_identity": self.get_caller_identity()
            }
        }
        
        # Try to log to Splunk HEC
        splunk_logged = False
        try:
            response = requests.post(self.hec_url, headers=self.headers, json=event_data, timeout=5)
            if response.status_code == 200:
                print(f"✅ AWS Attack logged to Splunk: {technique_id} - {technique_name}")
                splunk_logged = True
            else:
                print(f"⚠️ Failed to log to Splunk: HTTP {response.status_code}")
        except Exception as e:
            print(f"⚠️ Splunk logging error: {e}")
        
        # Always log to local file for backup
        self.log_to_file(event_data, splunk_logged)
        
        # Store for later analysis
        self.attack_results.append(event_data)
    
    def log_to_file(self, event_data: Dict, splunk_logged: bool = False):
        """Log AWS attack event to local file"""
        try:
            log_file = os.path.join(self.logs_dir, f"aws_attack_execution_{datetime.now().strftime('%Y%m%d')}.json")
            
            # Add local logging metadata
            event_data["logged_to_splunk"] = splunk_logged
            event_data["local_log_time"] = datetime.now().isoformat()
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(event_data) + '\n')
                
            if not splunk_logged:
                print(f"📝 AWS Attack logged locally: {event_data['event']['technique_id']}")
                
        except Exception as e:
            print(f"⚠️ Local logging error: {e}")
    
    def get_caller_identity(self) -> Dict:
        """Get current AWS caller identity"""
        try:
            if self.sts:
                return self.sts.get_caller_identity()
            return {"Account": "unknown", "UserId": "unknown", "Arn": "unknown"}
        except Exception as e:
            return {"error": str(e)}
    
    def execute_aws_command(self, command: str, timeout: int = 30) -> Dict:
        """Execute AWS CLI command and return results"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "command": command
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "return_code": -1,
                "command": command
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "command": command
            }
    
    def t1552_005_aws_credential_access(self):
        """T1552.005 - Credentials from Cloud Instance Metadata - REAL AWS API CALLS"""
        print("\n🔑 Executing T1552.005 - AWS Credential Access (REAL API CALLS)")
        
        # Real STS API calls for credential enumeration
        try:
            print("🔐 Getting caller identity...")
            identity = self.sts.get_caller_identity()
            result = {
                "success": True,
                "account": identity.get('Account'),
                "user_id": identity.get('UserId'),
                "arn": identity.get('Arn'),
                "api_call": "sts:GetCallerIdentity"
            }
            self.log_attack_event("T1552.005", "AWS Credential Access", "sts:GetCallerIdentity", result)
            print(f"✅ Account: {identity.get('Account')}, ARN: {identity.get('Arn')}")
        except Exception as e:
            result = {"success": False, "error": str(e), "api_call": "sts:GetCallerIdentity"}
            self.log_attack_event("T1552.005", "AWS Credential Access", "sts:GetCallerIdentity", result)
            print(f"❌ Failed: {e}")
        
        # Real IAM API calls
        try:
            print("👤 Getting current user details...")
            user = self.iam.get_user()
            result = {
                "success": True,
                "username": user['User']['UserName'],
                "user_id": user['User']['UserId'],
                "create_date": user['User']['CreateDate'].isoformat(),
                "api_call": "iam:GetUser"
            }
            self.log_attack_event("T1552.005", "AWS Credential Access", "iam:GetUser", result)
            print(f"✅ User: {user['User']['UserName']}")
            
            # List access keys for current user
            username = user['User']['UserName']
            keys = self.iam.list_access_keys(UserName=username)
            key_result = {
                "success": True,
                "username": username,
                "access_keys": [{"AccessKeyId": k['AccessKeyId'], "Status": k['Status']} for k in keys['AccessKeyMetadata']],
                "api_call": "iam:ListAccessKeys"
            }
            self.log_attack_event("T1552.005", "AWS Credential Access", "iam:ListAccessKeys", key_result)
            print(f"✅ Found {len(keys['AccessKeyMetadata'])} access keys")
            
        except Exception as e:
            result = {"success": False, "error": str(e), "api_call": "iam:GetUser"}
            self.log_attack_event("T1552.005", "AWS Credential Access", "iam:GetUser", result)
            print(f"❌ Failed: {e}")
        
        time.sleep(2)
    
    def t1580_cloud_infrastructure_discovery(self):
        """T1580 - Cloud Infrastructure Discovery - REAL AWS API CALLS"""
        print("\n🔍 Executing T1580 - Cloud Infrastructure Discovery (REAL API CALLS)")
        
        # Real EC2 API calls
        try:
            print("🖥️ Discovering EC2 instances...")
            instances_response = self.ec2.describe_instances(MaxResults=10)
            instances = []
            for reservation in instances_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append({
                        'InstanceId': instance.get('InstanceId'),
                        'InstanceType': instance.get('InstanceType'),
                        'State': instance.get('State', {}).get('Name'),
                        'PrivateIpAddress': instance.get('PrivateIpAddress'),
                        'PublicIpAddress': instance.get('PublicIpAddress')
                    })
            
            result = {
                "success": True,
                "instances_found": len(instances),
                "instances": instances,
                "api_call": "ec2:DescribeInstances"
            }
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "ec2:DescribeInstances", result)
            print(f"✅ Found {len(instances)} EC2 instances")
        except Exception as e:
            result = {"success": False, "error": str(e), "api_call": "ec2:DescribeInstances"}
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "ec2:DescribeInstances", result)
            print(f"❌ EC2 Discovery failed: {e}")
        
        # Real S3 API calls
        try:
            print("🪣 Discovering S3 buckets...")
            buckets_response = self.s3.list_buckets()
            buckets = []
            for bucket in buckets_response.get('Buckets', []):
                buckets.append({
                    'Name': bucket.get('Name'),
                    'CreationDate': bucket.get('CreationDate').isoformat() if bucket.get('CreationDate') else None
                })
            
            result = {
                "success": True,
                "buckets_found": len(buckets),
                "buckets": buckets,
                "api_call": "s3:ListBuckets"
            }
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "s3:ListBuckets", result)
            print(f"✅ Found {len(buckets)} S3 buckets")
        except Exception as e:
            result = {"success": False, "error": str(e), "api_call": "s3:ListBuckets"}
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "s3:ListBuckets", result)
            print(f"❌ S3 Discovery failed: {e}")
        
        # Real IAM API calls
        try:
            print("👥 Discovering IAM users...")
            users_response = self.iam.list_users(MaxItems=10)
            users = []
            for user in users_response.get('Users', []):
                users.append({
                    'UserName': user.get('UserName'),
                    'UserId': user.get('UserId'),
                    'CreateDate': user.get('CreateDate').isoformat() if user.get('CreateDate') else None
                })
            
            result = {
                "success": True,
                "users_found": len(users),
                "users": users,
                "api_call": "iam:ListUsers"
            }
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "iam:ListUsers", result)
            print(f"✅ Found {len(users)} IAM users")
        except Exception as e:
            result = {"success": False, "error": str(e), "api_call": "iam:ListUsers"}
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "iam:ListUsers", result)
            print(f"❌ IAM Discovery failed: {e}")
        
        # Real RDS API calls
        try:
            print("🗄️ Discovering RDS instances...")
            rds_response = self.rds.describe_db_instances(MaxRecords=5)
            rds_instances = []
            for db in rds_response.get('DBInstances', []):
                rds_instances.append({
                    'DBInstanceIdentifier': db.get('DBInstanceIdentifier'),
                    'DBInstanceClass': db.get('DBInstanceClass'),
                    'Engine': db.get('Engine'),
                    'DBInstanceStatus': db.get('DBInstanceStatus')
                })
            
            result = {
                "success": True,
                "rds_instances_found": len(rds_instances),
                "rds_instances": rds_instances,
                "api_call": "rds:DescribeDBInstances"
            }
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "rds:DescribeDBInstances", result)
            print(f"✅ Found {len(rds_instances)} RDS instances")
        except Exception as e:
            result = {"success": False, "error": str(e), "api_call": "rds:DescribeDBInstances"}
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "rds:DescribeDBInstances", result)
            print(f"❌ RDS Discovery failed: {e}")
        
        # Real Lambda API calls
        try:
            print("⚡ Discovering Lambda functions...")
            lambda_response = self.lambda_client.list_functions(MaxItems=10)
            functions = []
            for func in lambda_response.get('Functions', []):
                functions.append({
                    'FunctionName': func.get('FunctionName'),
                    'Runtime': func.get('Runtime'),
                    'LastModified': func.get('LastModified'),
                    'CodeSize': func.get('CodeSize')
                })
            
            result = {
                "success": True,
                "functions_found": len(functions),
                "functions": functions,
                "api_call": "lambda:ListFunctions"
            }
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "lambda:ListFunctions", result)
            print(f"✅ Found {len(functions)} Lambda functions")
        except Exception as e:
            result = {"success": False, "error": str(e), "api_call": "lambda:ListFunctions"}
            self.log_attack_event("T1580", "Cloud Infrastructure Discovery", "lambda:ListFunctions", result)
            print(f"❌ Lambda Discovery failed: {e}")
        
        time.sleep(2)
    
    def t1098_001_aws_account_manipulation(self):
        """T1098.001 - Additional Cloud Credentials (Simulation)"""
        print("\n👤 Executing T1098.001 - AWS Account Manipulation (Simulation)")
        
        # Note: These are read-only operations for safety
        manipulation_commands = [
            "aws iam list-access-keys --max-items 10",
            "aws iam list-users --max-items 10",
            "aws iam get-account-summary",
            "aws iam list-policies --scope Local --max-items 10",
            "aws iam list-groups --max-items 10"
        ]
        
        for cmd in manipulation_commands:
            print(f"Executing (Read-only): {cmd}")
            result = self.execute_aws_command(cmd)
            self.log_attack_event("T1098.001", "AWS Account Manipulation", cmd, result)
            time.sleep(1)
        
        print("⚠️ Note: Actual user/policy creation skipped for safety")
    
    def t1537_aws_data_transfer(self):
        """T1537 - Transfer Data to Cloud Account (Simulation)"""
        print("\n📤 Executing T1537 - AWS Data Transfer (Simulation)")
        
        # Safe S3 enumeration commands
        data_commands = [
            "aws s3 ls",
            "aws s3api list-buckets",
            "aws s3api get-bucket-location --bucket $(aws s3 ls | head -1 | awk '{print $3}') 2>/dev/null || echo 'No accessible buckets'",
            "aws s3api get-bucket-acl --bucket $(aws s3 ls | head -1 | awk '{print $3}') 2>/dev/null || echo 'Cannot access bucket ACL'"
        ]
        
        for cmd in data_commands:
            print(f"Executing: {cmd}")
            result = self.execute_aws_command(cmd)
            self.log_attack_event("T1537", "AWS Data Transfer", cmd, result)
            time.sleep(1)
        
        print("⚠️ Note: Actual data transfer skipped for safety")
    
    def t1562_008_aws_disable_security_tools(self):
        """T1562.008 - Disable Cloud Logs (Simulation)"""
        print("\n🛡️ Executing T1562.008 - AWS Disable Security Tools (Simulation)")
        
        # Read-only security service enumeration
        security_commands = [
            "aws cloudtrail describe-trails",
            "aws guardduty list-detectors",
            "aws config describe-configuration-recorders",
            "aws logs describe-log-groups --max-items 10",
            "aws securityhub get-enabled-standards 2>/dev/null || echo 'SecurityHub not available'",
            "aws inspector list-assessment-templates 2>/dev/null || echo 'Inspector not available'"
        ]
        
        for cmd in security_commands:
            print(f"Executing (Read-only): {cmd}")
            result = self.execute_aws_command(cmd)
            self.log_attack_event("T1562.008", "AWS Disable Security Tools", cmd, result)
            time.sleep(1)
        
        print("⚠️ Note: Actual security service disabling skipped for safety")
    
    def t1021_007_aws_lateral_movement(self):
        """T1021.007 - Cloud Services (Simulation)"""
        print("\n↔️ Executing T1021.007 - AWS Lateral Movement (Simulation)")
        
        # Safe service enumeration for lateral movement assessment
        lateral_commands = [
            "aws ssm describe-instance-information --max-items 10",
            "aws ecs list-clusters",
            "aws ecs list-services --cluster $(aws ecs list-clusters --query 'clusterArns[0]' --output text 2>/dev/null) 2>/dev/null || echo 'No ECS clusters'",
            "aws lambda list-functions --max-items 10",
            "aws rds describe-db-instances --max-items 5"
        ]
        
        for cmd in lateral_commands:
            print(f"Executing: {cmd}")
            result = self.execute_aws_command(cmd)
            self.log_attack_event("T1021.007", "AWS Lateral Movement", cmd, result)
            time.sleep(1)
        
        print("⚠️ Note: Actual lateral movement commands skipped for safety")
    
    def perform_aws_environment_assessment(self):
        """Perform comprehensive AWS environment assessment"""
        print("\n🔍 AWS Environment Assessment")
        
        assessment_commands = [
            "aws sts get-caller-identity",
            "aws iam get-account-summary",
            "aws ec2 describe-regions",
            "aws organizations describe-organization 2>/dev/null || echo 'Not in organization'",
            "aws support describe-trusted-advisor-checks --language en 2>/dev/null || echo 'Support API not available'"
        ]
        
        for cmd in assessment_commands:
            print(f"Executing: {cmd}")
            result = self.execute_aws_command(cmd)
            self.log_attack_event("T1580", "AWS Environment Assessment", cmd, result)
            time.sleep(1)
    
    def export_aws_attack_summary(self):
        """Export a summary of all AWS attacks executed"""
        summary_file = os.path.join(self.logs_dir, f"aws_attack_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        summary = {
            "aws_execution_summary": {
                "total_attacks": len(self.attack_results),
                "execution_time": datetime.now().isoformat(),
                "techniques_executed": list(set([event['event']['technique_id'] for event in self.attack_results])),
                "commands_executed": len([event for event in self.attack_results if event['event']['execution_result']['success']]),
                "failed_commands": len([event for event in self.attack_results if not event['event']['execution_result']['success']]),
                "aws_identity": self.get_caller_identity()
            },
            "detailed_results": self.attack_results
        }
        
        try:
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"📊 AWS Attack summary exported to: {summary_file}")
        except Exception as e:
            print(f"⚠️ Failed to export AWS summary: {e}")
    
    def run_comprehensive_aws_attack_simulation(self):
        """Execute comprehensive AWS attack simulation with REAL credentials"""
        print("🚨 STARTING REAL AWS ATTACK SIMULATION - 100% GENUINE API CALLS")
        print("=" * 70)
        print("⚠️  WARNING: Using REAL AWS credentials and making ACTUAL API calls")
        print("🔐 Account: 703671926666 (deploy_splunk_user)")
        print("🌍 Region: us-east-1")
        print("⚠️  All attack techniques will perform REAL AWS operations")
        print("=" * 70)
        
        # Check AWS credentials
        identity = self.get_caller_identity()
        if 'error' in identity:
            print(f"❌ AWS credentials not configured: {identity['error']}")
            return
        
        print(f"✅ AWS Identity: {identity.get('Arn', 'Unknown')}")
        
        # Execute attack techniques in sequence
        attack_techniques = [
            self.perform_aws_environment_assessment,
            self.t1552_005_aws_credential_access,
            self.t1580_cloud_infrastructure_discovery,
            self.t1098_001_aws_account_manipulation,
            self.t1537_aws_data_transfer,
            self.t1562_008_aws_disable_security_tools,
            self.t1021_007_aws_lateral_movement
        ]
        
        for technique in attack_techniques:
            try:
                technique()
                time.sleep(5)  # Pause between techniques
            except Exception as e:
                print(f"❌ Error executing technique: {e}")
                continue
        
        print("\n✅ REAL AWS ATTACK SIMULATION COMPLETE")
        print(f"📊 Total techniques executed: {len(attack_techniques)}")
        print("📝 All activities logged locally and to Splunk (if available)")
        print("🔍 Check CloudTrail logs for detailed API call records")
        
        # Export summary
        self.export_aws_attack_summary()
        
        # Show log locations
        print(f"\n📂 AWS Attack logs saved to: {self.logs_dir}/")
        print("📁 Log files created:")
        try:
            for log_file in os.listdir(self.logs_dir):
                if 'aws_attack' in log_file:
                    print(f"  - {log_file}")
        except Exception as e:
            print(f"  Could not list log files: {e}")

def main():
    """Main execution function"""
    print("🎯 AWS Attack Executor - Real AWS Attack Technique Implementation")
    print("⚠️  This tool executes REAL AWS API calls - use only in authorized environments")
    
    # Initialize executor
    executor = AWSAttackExecutor()
    
    # Run comprehensive simulation
    executor.run_comprehensive_aws_attack_simulation()

if __name__ == "__main__":
    main() 