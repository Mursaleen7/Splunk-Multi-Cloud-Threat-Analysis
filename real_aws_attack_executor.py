#!/usr/bin/env python3
"""
REAL AWS Attack Executor - GENUINE AWS API OPERATIONS
Performs actual AWS API calls using real credentials for security testing
"""

import boto3
import json
import time
import os
import random
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError

class RealAWSAttackExecutor:
    def __init__(self):
        # AWS Credentials from the provided files
        self.aws_access_key = "AKIA2HVQ5P6FNAE6FOM7"
        self.aws_secret_key = "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"
        self.aws_region = "us-east-1"  # Default region
        self.account_id = "703671926666"
        
        # Initialize AWS session with real credentials
        self.session = boto3.Session(
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.aws_region
        )
        
        # AWS clients for different services
        self.clients = {}
        
        # Real MITRE ATT&CK techniques with actual AWS operations
        self.attack_techniques = {
            "T1580": {
                "name": "AWS Cloud Infrastructure Discovery",
                "operations": [
                    self.discover_ec2_instances,
                    self.discover_s3_buckets,
                    self.discover_iam_users,
                    self.discover_rds_instances,
                    self.discover_vpc_resources
                ],
                "severity": "HIGH"
            },
            "T1552.005": {
                "name": "AWS Credential Access via STS",
                "operations": [
                    self.get_caller_identity,
                    self.list_access_keys,
                    self.get_account_summary
                ],
                "severity": "CRITICAL"
            },
            "T1078.004": {
                "name": "Valid Cloud Accounts Discovery",
                "operations": [
                    self.enumerate_iam_roles,
                    self.list_attached_policies,
                    self.get_user_policies
                ],
                "severity": "HIGH"
            },
            "T1526": {
                "name": "Cloud Service Discovery",
                "operations": [
                    self.discover_cloudformation_stacks,
                    self.discover_lambda_functions,
                    self.discover_cloudwatch_logs
                ],
                "severity": "MEDIUM"
            }
        }
        
        # Ensure attack_logs directory exists
        os.makedirs("attack_logs", exist_ok=True)
        
    def get_aws_client(self, service_name):
        """Get or create AWS client for a service"""
        if service_name not in self.clients:
            try:
                self.clients[service_name] = self.session.client(service_name)
            except Exception as e:
                print(f"⚠️ Failed to create {service_name} client: {e}")
                return None
        return self.clients[service_name]
    
    def discover_ec2_instances(self):
        """T1580 - Discover EC2 instances (REAL AWS API CALL)"""
        try:
            ec2 = self.get_aws_client('ec2')
            if not ec2:
                return self.create_error_result("EC2 client unavailable")
            
            response = ec2.describe_instances()
            
            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append({
                        'InstanceId': instance.get('InstanceId'),
                        'InstanceType': instance.get('InstanceType'),
                        'State': instance.get('State', {}).get('Name'),
                        'PrivateIpAddress': instance.get('PrivateIpAddress'),
                        'PublicIpAddress': instance.get('PublicIpAddress')
                    })
            
            return {
                'success': True,
                'operation': 'ec2:DescribeInstances',
                'instances_found': len(instances),
                'instances': instances[:5],  # Limit output
                'total_reservations': len(response.get('Reservations', []))
            }
            
        except ClientError as e:
            return self.create_error_result(f"EC2 Discovery failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def discover_s3_buckets(self):
        """T1580 - Discover S3 buckets (REAL AWS API CALL)"""
        try:
            s3 = self.get_aws_client('s3')
            if not s3:
                return self.create_error_result("S3 client unavailable")
            
            response = s3.list_buckets()
            
            buckets = []
            for bucket in response.get('Buckets', []):
                bucket_info = {
                    'Name': bucket.get('Name'),
                    'CreationDate': bucket.get('CreationDate').isoformat() if bucket.get('CreationDate') else None
                }
                
                # Try to get bucket location (additional recon)
                try:
                    location = s3.get_bucket_location(Bucket=bucket['Name'])
                    bucket_info['Region'] = location.get('LocationConstraint', 'us-east-1')
                except:
                    bucket_info['Region'] = 'Unknown'
                
                buckets.append(bucket_info)
            
            return {
                'success': True,
                'operation': 's3:ListBuckets',
                'buckets_found': len(buckets),
                'buckets': buckets
            }
            
        except ClientError as e:
            return self.create_error_result(f"S3 Discovery failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def discover_iam_users(self):
        """T1580 - Discover IAM users (REAL AWS API CALL)"""
        try:
            iam = self.get_aws_client('iam')
            if not iam:
                return self.create_error_result("IAM client unavailable")
            
            response = iam.list_users()
            
            users = []
            for user in response.get('Users', []):
                users.append({
                    'UserName': user.get('UserName'),
                    'UserId': user.get('UserId'),
                    'CreateDate': user.get('CreateDate').isoformat() if user.get('CreateDate') else None,
                    'Path': user.get('Path')
                })
            
            return {
                'success': True,
                'operation': 'iam:ListUsers',
                'users_found': len(users),
                'users': users
            }
            
        except ClientError as e:
            return self.create_error_result(f"IAM Discovery failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def discover_rds_instances(self):
        """T1580 - Discover RDS instances (REAL AWS API CALL)"""
        try:
            rds = self.get_aws_client('rds')
            if not rds:
                return self.create_error_result("RDS client unavailable")
            
            response = rds.describe_db_instances()
            
            instances = []
            for db in response.get('DBInstances', []):
                instances.append({
                    'DBInstanceIdentifier': db.get('DBInstanceIdentifier'),
                    'DBInstanceClass': db.get('DBInstanceClass'),
                    'Engine': db.get('Engine'),
                    'DBInstanceStatus': db.get('DBInstanceStatus'),
                    'Endpoint': db.get('Endpoint', {}).get('Address') if db.get('Endpoint') else None
                })
            
            return {
                'success': True,
                'operation': 'rds:DescribeDBInstances',
                'instances_found': len(instances),
                'instances': instances
            }
            
        except ClientError as e:
            return self.create_error_result(f"RDS Discovery failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def discover_vpc_resources(self):
        """T1580 - Discover VPC resources (REAL AWS API CALL)"""
        try:
            ec2 = self.get_aws_client('ec2')
            if not ec2:
                return self.create_error_result("EC2 client unavailable")
            
            vpcs_response = ec2.describe_vpcs()
            subnets_response = ec2.describe_subnets()
            
            vpcs = []
            for vpc in vpcs_response.get('Vpcs', []):
                vpcs.append({
                    'VpcId': vpc.get('VpcId'),
                    'CidrBlock': vpc.get('CidrBlock'),
                    'State': vpc.get('State'),
                    'IsDefault': vpc.get('IsDefault')
                })
            
            return {
                'success': True,
                'operation': 'ec2:DescribeVpcs',
                'vpcs_found': len(vpcs),
                'subnets_found': len(subnets_response.get('Subnets', [])),
                'vpcs': vpcs
            }
            
        except ClientError as e:
            return self.create_error_result(f"VPC Discovery failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def get_caller_identity(self):
        """T1552.005 - Get caller identity (REAL AWS API CALL)"""
        try:
            sts = self.get_aws_client('sts')
            if not sts:
                return self.create_error_result("STS client unavailable")
            
            response = sts.get_caller_identity()
            
            return {
                'success': True,
                'operation': 'sts:GetCallerIdentity',
                'account': response.get('Account'),
                'user_id': response.get('UserId'),
                'arn': response.get('Arn')
            }
            
        except ClientError as e:
            return self.create_error_result(f"STS GetCallerIdentity failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def list_access_keys(self):
        """T1552.005 - List access keys for current user (REAL AWS API CALL)"""
        try:
            iam = self.get_aws_client('iam')
            if not iam:
                return self.create_error_result("IAM client unavailable")
            
            # Get current user first
            user_response = iam.get_user()
            username = user_response['User']['UserName']
            
            # List access keys for current user
            response = iam.list_access_keys(UserName=username)
            
            keys = []
            for key in response.get('AccessKeyMetadata', []):
                keys.append({
                    'AccessKeyId': key.get('AccessKeyId'),
                    'Status': key.get('Status'),
                    'CreateDate': key.get('CreateDate').isoformat() if key.get('CreateDate') else None
                })
            
            return {
                'success': True,
                'operation': 'iam:ListAccessKeys',
                'username': username,
                'access_keys_found': len(keys),
                'access_keys': keys
            }
            
        except ClientError as e:
            return self.create_error_result(f"Access Key enumeration failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def get_account_summary(self):
        """T1552.005 - Get account summary (REAL AWS API CALL)"""
        try:
            iam = self.get_aws_client('iam')
            if not iam:
                return self.create_error_result("IAM client unavailable")
            
            response = iam.get_account_summary()
            
            return {
                'success': True,
                'operation': 'iam:GetAccountSummary',
                'summary': response.get('SummaryMap', {})
            }
            
        except ClientError as e:
            return self.create_error_result(f"Account summary failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def enumerate_iam_roles(self):
        """T1078.004 - Enumerate IAM roles (REAL AWS API CALL)"""
        try:
            iam = self.get_aws_client('iam')
            if not iam:
                return self.create_error_result("IAM client unavailable")
            
            response = iam.list_roles()
            
            roles = []
            for role in response.get('Roles', []):
                roles.append({
                    'RoleName': role.get('RoleName'),
                    'RoleId': role.get('RoleId'),
                    'CreateDate': role.get('CreateDate').isoformat() if role.get('CreateDate') else None,
                    'Path': role.get('Path')
                })
            
            return {
                'success': True,
                'operation': 'iam:ListRoles',
                'roles_found': len(roles),
                'roles': roles[:10]  # Limit output
            }
            
        except ClientError as e:
            return self.create_error_result(f"Role enumeration failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def list_attached_policies(self):
        """T1078.004 - List attached policies (REAL AWS API CALL)"""
        try:
            iam = self.get_aws_client('iam')
            if not iam:
                return self.create_error_result("IAM client unavailable")
            
            # Get current user first
            user_response = iam.get_user()
            username = user_response['User']['UserName']
            
            # List attached policies
            response = iam.list_attached_user_policies(UserName=username)
            
            policies = []
            for policy in response.get('AttachedPolicies', []):
                policies.append({
                    'PolicyName': policy.get('PolicyName'),
                    'PolicyArn': policy.get('PolicyArn')
                })
            
            return {
                'success': True,
                'operation': 'iam:ListAttachedUserPolicies',
                'username': username,
                'policies_found': len(policies),
                'policies': policies
            }
            
        except ClientError as e:
            return self.create_error_result(f"Policy enumeration failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def get_user_policies(self):
        """T1078.004 - Get inline user policies (REAL AWS API CALL)"""
        try:
            iam = self.get_aws_client('iam')
            if not iam:
                return self.create_error_result("IAM client unavailable")
            
            # Get current user first
            user_response = iam.get_user()
            username = user_response['User']['UserName']
            
            # List inline policies
            response = iam.list_user_policies(UserName=username)
            
            return {
                'success': True,
                'operation': 'iam:ListUserPolicies',
                'username': username,
                'inline_policies': response.get('PolicyNames', [])
            }
            
        except ClientError as e:
            return self.create_error_result(f"User policy enumeration failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def discover_cloudformation_stacks(self):
        """T1526 - Discover CloudFormation stacks (REAL AWS API CALL)"""
        try:
            cf = self.get_aws_client('cloudformation')
            if not cf:
                return self.create_error_result("CloudFormation client unavailable")
            
            response = cf.list_stacks()
            
            stacks = []
            for stack in response.get('StackSummaries', []):
                if stack.get('StackStatus') != 'DELETE_COMPLETE':
                    stacks.append({
                        'StackName': stack.get('StackName'),
                        'StackStatus': stack.get('StackStatus'),
                        'CreationTime': stack.get('CreationTime').isoformat() if stack.get('CreationTime') else None
                    })
            
            return {
                'success': True,
                'operation': 'cloudformation:ListStacks',
                'stacks_found': len(stacks),
                'stacks': stacks
            }
            
        except ClientError as e:
            return self.create_error_result(f"CloudFormation discovery failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def discover_lambda_functions(self):
        """T1526 - Discover Lambda functions (REAL AWS API CALL)"""
        try:
            lambda_client = self.get_aws_client('lambda')
            if not lambda_client:
                return self.create_error_result("Lambda client unavailable")
            
            response = lambda_client.list_functions()
            
            functions = []
            for func in response.get('Functions', []):
                functions.append({
                    'FunctionName': func.get('FunctionName'),
                    'Runtime': func.get('Runtime'),
                    'LastModified': func.get('LastModified'),
                    'CodeSize': func.get('CodeSize')
                })
            
            return {
                'success': True,
                'operation': 'lambda:ListFunctions',
                'functions_found': len(functions),
                'functions': functions
            }
            
        except ClientError as e:
            return self.create_error_result(f"Lambda discovery failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def discover_cloudwatch_logs(self):
        """T1526 - Discover CloudWatch log groups (REAL AWS API CALL)"""
        try:
            logs = self.get_aws_client('logs')
            if not logs:
                return self.create_error_result("CloudWatch Logs client unavailable")
            
            response = logs.describe_log_groups()
            
            log_groups = []
            for lg in response.get('logGroups', []):
                log_groups.append({
                    'logGroupName': lg.get('logGroupName'),
                    'creationTime': lg.get('creationTime'),
                    'storedBytes': lg.get('storedBytes', 0)
                })
            
            return {
                'success': True,
                'operation': 'logs:DescribeLogGroups',
                'log_groups_found': len(log_groups),
                'log_groups': log_groups[:10]  # Limit output
            }
            
        except ClientError as e:
            return self.create_error_result(f"CloudWatch Logs discovery failed: {str(e)}")
        except Exception as e:
            return self.create_error_result(f"Unexpected error: {str(e)}")
    
    def create_error_result(self, error_message):
        """Create standardized error result"""
        return {
            'success': False,
            'error': error_message,
            'operation': 'failed'
        }
    
    def execute_attack_technique(self, technique_id):
        """Execute a real AWS attack technique"""
        if technique_id not in self.attack_techniques:
            return None
        
        technique = self.attack_techniques[technique_id]
        operation = random.choice(technique["operations"])
        
        print(f"\n☁️ Executing {technique_id} - {technique['name']}")
        print(f"Operation: {operation.__name__}")
        
        try:
            result = operation()
            
            attack_event = {
                "technique_id": technique_id,
                "technique_name": technique["name"],
                "aws_operation": operation.__name__,
                "aws_region": self.aws_region,
                "execution_result": result,
                "severity": technique["severity"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "attack_type": "REAL_AWS_EXECUTION",
                "host": f"aws-{self.aws_region}",
                "user": "deploy_splunk_user",
                "aws_account_id": self.account_id,
                "event_source": "real.aws.api"
            }
            
            success_indicator = "✅ Success" if result.get('success') else "❌ Failed"
            print(f"Result: {success_indicator}")
            if not result.get('success'):
                print(f"Error: {result.get('error', 'Unknown error')}")
            else:
                print(f"Operation: {result.get('operation', 'N/A')}")
            
            return {
                "time": int(time.time()),
                "sourcetype": "real_aws_attack_execution",
                "source": "real_aws_attack_executor",
                "event": attack_event,
                "logged_to_splunk": False,
                "local_log_time": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            print(f"❌ Technique execution failed: {e}")
            return None
    
    def execute_real_aws_attacks(self, num_attacks=15):
        """Execute real AWS attack simulation"""
        print("☁️ REAL AWS Attack Executor - GENUINE AWS API OPERATIONS")
        print("⚠️  This performs REAL AWS API calls using actual credentials")
        print("🚨 STARTING REAL AWS ATTACK EXECUTION")
        print("=" * 60)
        
        # Test AWS connectivity first
        print("\n🔐 Testing AWS connectivity...")
        try:
            sts = self.get_aws_client('sts')
            identity = sts.get_caller_identity()
            print(f"✅ Connected to AWS Account: {identity.get('Account')}")
            print(f"✅ User ARN: {identity.get('Arn')}")
        except Exception as e:
            print(f"❌ AWS connectivity test failed: {e}")
            return []
        
        attacks_executed = 0
        log_entries = []
        
        techniques = list(self.attack_techniques.keys())
        
        for i in range(num_attacks):
            technique_id = random.choice(techniques)
            
            event = self.execute_attack_technique(technique_id)
            if event:
                log_entries.append(event)
                attacks_executed += 1
                print(f"📝 Real AWS attack logged: {technique_id}")
            
            # Delay between attacks to avoid rate limiting
            time.sleep(random.uniform(1.0, 3.0))
        
        # Save to log file
        today = datetime.now().strftime("%Y%m%d")
        log_file = f"attack_logs/real_aws_attack_execution_{today}.json"
        
        with open(log_file, 'w') as f:
            for entry in log_entries:
                f.write(json.dumps(entry) + '\n')
        
        print(f"\n✅ REAL AWS ATTACK EXECUTION COMPLETE")
        print(f"📊 Total techniques executed: {attacks_executed}")
        print(f"📝 All activities logged to: {log_file}")
        
        # Summary statistics
        successful_attacks = sum(1 for entry in log_entries if entry["event"]["execution_result"].get("success"))
        failed_attacks = attacks_executed - successful_attacks
        
        print(f"\n📈 REAL AWS ATTACK STATISTICS:")
        print(f"✅ Successful: {successful_attacks}")
        print(f"❌ Failed: {failed_attacks}")
        print(f"📊 Success Rate: {(successful_attacks/attacks_executed)*100:.1f}%")
        
        return log_entries

def main():
    executor = RealAWSAttackExecutor()
    executor.execute_real_aws_attacks(20)  # Execute 20 real AWS operations

if __name__ == "__main__":
    main() 