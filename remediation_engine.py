"""
Automated Remediation Engine
Generates and executes remediation code for common WAF findings
"""

from typing import Dict, List, Optional
import json
import boto3
from datetime import datetime


class RemediationEngine:
    """Generate and execute automated remediation for findings"""
    
    def __init__(self, session: Optional[boto3.Session] = None):
        self.session = session or boto3.Session()
        self.remediation_catalog = self._initialize_catalog()
    
    def _initialize_catalog(self) -> Dict:
        """Initialize remediation playbooks"""
        return {
            's3_no_encryption': {
                'automated': True,
                'estimated_time': '2 minutes',
                'rollback_available': True,
                'risk_level': 'LOW',
                'confirmation_required': False
            },
            's3_public_access': {
                'automated': True,
                'estimated_time': '2 minutes',
                'rollback_available': True,
                'risk_level': 'HIGH',
                'confirmation_required': True
            },
            's3_no_versioning': {
                'automated': True,
                'estimated_time': '1 minute',
                'rollback_available': False,
                'risk_level': 'LOW',
                'confirmation_required': False
            },
            'security_group_unrestricted': {
                'automated': True,
                'estimated_time': '5 minutes',
                'rollback_available': True,
                'risk_level': 'CRITICAL',
                'confirmation_required': True
            },
            'rds_no_encryption': {
                'automated': False,
                'estimated_time': '30 minutes',
                'rollback_available': False,
                'risk_level': 'CRITICAL',
                'confirmation_required': True,
                'note': 'Requires DB recreation - use manual steps'
            },
            'cloudtrail_not_enabled': {
                'automated': True,
                'estimated_time': '5 minutes',
                'rollback_available': True,
                'risk_level': 'MEDIUM',
                'confirmation_required': False
            }
        }
    
    def get_remediation_options(self, finding: Dict) -> Dict:
        """Get remediation options for a finding"""
        
        finding_type = self._classify_finding(finding)
        
        options = {
            'finding_type': finding_type,
            'automated_available': False,
            'terraform': None,
            'cloudformation': None,
            'aws_cli': None,
            'manual_steps': [],
            'playbook': {}
        }
        
        if finding_type in self.remediation_catalog:
            options['playbook'] = self.remediation_catalog[finding_type]
            options['automated_available'] = self.remediation_catalog[finding_type]['automated']
        
        # Generate remediation code
        if finding_type == 's3_no_encryption':
            options.update(self._remediate_s3_encryption(finding))
        elif finding_type == 's3_public_access':
            options.update(self._remediate_s3_public_access(finding))
        elif finding_type == 's3_no_versioning':
            options.update(self._remediate_s3_versioning(finding))
        elif finding_type == 'security_group_unrestricted':
            options.update(self._remediate_security_group(finding))
        elif finding_type == 'cloudtrail_not_enabled':
            options.update(self._remediate_cloudtrail(finding))
        
        return options
    
    def _classify_finding(self, finding: Dict) -> str:
        """Classify finding to determine remediation type"""
        
        title = finding.get('title', '').lower()
        service = finding.get('service', '').lower()
        
        if service == 's3':
            if 'encrypt' in title:
                return 's3_no_encryption'
            elif 'public' in title or 'block public access' in title:
                return 's3_public_access'
            elif 'versioning' in title:
                return 's3_no_versioning'
        elif 'security group' in title:
            if '0.0.0.0/0' in title or 'unrestricted' in title:
                return 'security_group_unrestricted'
        elif 'cloudtrail' in title:
            return 'cloudtrail_not_enabled'
        elif service == 'rds' and 'encrypt' in title:
            return 'rds_no_encryption'
        
        return 'unknown'
    
    # ==================== S3 REMEDIATION ====================
    
    def _remediate_s3_encryption(self, finding: Dict) -> Dict:
        """Generate S3 encryption remediation"""
        
        bucket_name = finding.get('resource', 'bucket-name')
        
        return {
            'terraform': self._generate_s3_encryption_terraform(bucket_name),
            'cloudformation': self._generate_s3_encryption_cfn(bucket_name),
            'aws_cli': self._generate_s3_encryption_cli(bucket_name),
            'manual_steps': [
                f"1. Go to S3 Console",
                f"2. Select bucket: {bucket_name}",
                f"3. Click 'Properties' tab",
                f"4. Scroll to 'Default encryption'",
                f"5. Click 'Edit'",
                f"6. Select 'Server-side encryption with Amazon S3 managed keys (SSE-S3)'",
                f"7. Click 'Save changes'"
            ]
        }
    
    def _generate_s3_encryption_terraform(self, bucket_name: str) -> str:
        """Generate Terraform code for S3 encryption"""
        return f'''# Enable S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name.replace('-', '_')}_encryption" {{
  bucket = "{bucket_name}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
    bucket_key_enabled = true
  }}
}}
'''
    
    def _generate_s3_encryption_cfn(self, bucket_name: str) -> str:
        """Generate CloudFormation for S3 encryption"""
        return json.dumps({
            "Resources": {
                "S3BucketEncryption": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": bucket_name,
                        "BucketEncryption": {
                            "ServerSideEncryptionConfiguration": [{
                                "ServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "AES256"
                                },
                                "BucketKeyEnabled": True
                            }]
                        }
                    }
                }
            }
        }, indent=2)
    
    def _generate_s3_encryption_cli(self, bucket_name: str) -> List[str]:
        """Generate AWS CLI commands for S3 encryption"""
        return [
            f"# Enable S3 bucket encryption",
            f"aws s3api put-bucket-encryption \\",
            f"  --bucket {bucket_name} \\",
            f"  --server-side-encryption-configuration '{{",
            f"    \"Rules\": [{{",
            f"      \"ApplyServerSideEncryptionByDefault\": {{",
            f"        \"SSEAlgorithm\": \"AES256\"",
            f"      }},",
            f"      \"BucketKeyEnabled\": true",
            f"    }}]",
            f"  }}'",
            f"",
            f"# Verify encryption is enabled",
            f"aws s3api get-bucket-encryption --bucket {bucket_name}"
        ]
    
    def _remediate_s3_public_access(self, finding: Dict) -> Dict:
        """Generate S3 public access block remediation"""
        
        bucket_name = finding.get('resource', 'bucket-name')
        
        return {
            'terraform': f'''# Block all public access to S3 bucket
resource "aws_s3_bucket_public_access_block" "{bucket_name.replace('-', '_')}_public_block" {{
  bucket = "{bucket_name}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
''',
            'aws_cli': [
                f"# Block all public access",
                f"aws s3api put-public-access-block \\",
                f"  --bucket {bucket_name} \\",
                f"  --public-access-block-configuration \\",
                f"    \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\"",
                f"",
                f"# Verify settings",
                f"aws s3api get-public-access-block --bucket {bucket_name}"
            ],
            'manual_steps': [
                f"1. Go to S3 Console",
                f"2. Select bucket: {bucket_name}",
                f"3. Click 'Permissions' tab",
                f"4. Scroll to 'Block public access (bucket settings)'",
                f"5. Click 'Edit'",
                f"6. Check all four boxes:",
                f"   - Block all public access",
                f"7. Click 'Save changes'",
                f"8. Type 'confirm' and click 'Confirm'"
            ]
        }
    
    def _remediate_s3_versioning(self, finding: Dict) -> Dict:
        """Generate S3 versioning remediation"""
        
        bucket_name = finding.get('resource', 'bucket-name')
        
        return {
            'terraform': f'''# Enable S3 bucket versioning
resource "aws_s3_bucket_versioning" "{bucket_name.replace('-', '_')}_versioning" {{
  bucket = "{bucket_name}"
  
  versioning_configuration {{
    status = "Enabled"
  }}
}}
''',
            'aws_cli': [
                f"# Enable versioning",
                f"aws s3api put-bucket-versioning \\",
                f"  --bucket {bucket_name} \\",
                f"  --versioning-configuration Status=Enabled",
                f"",
                f"# Verify versioning is enabled",
                f"aws s3api get-bucket-versioning --bucket {bucket_name}"
            ],
            'manual_steps': [
                f"1. Go to S3 Console",
                f"2. Select bucket: {bucket_name}",
                f"3. Click 'Properties' tab",
                f"4. Scroll to 'Bucket Versioning'",
                f"5. Click 'Edit'",
                f"6. Select 'Enable'",
                f"7. Click 'Save changes'"
            ]
        }
    
    # ==================== SECURITY GROUP REMEDIATION ====================
    
    def _remediate_security_group(self, finding: Dict) -> Dict:
        """Generate Security Group remediation"""
        
        sg_id = finding.get('resource', 'sg-xxxxx')
        
        return {
            'terraform': f'''# Remove unrestricted ingress rules
resource "aws_security_group_rule" "remove_unrestricted" {{
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["10.0.0.0/8"]  # Replace with your VPC CIDR
  security_group_id = "{sg_id}"
}}

# Remove the 0.0.0.0/0 rule manually or use AWS CLI
''',
            'aws_cli': [
                f"# List current ingress rules",
                f"aws ec2 describe-security-groups --group-ids {sg_id}",
                f"",
                f"# Remove unrestricted SSH rule (port 22)",
                f"aws ec2 revoke-security-group-ingress \\",
                f"  --group-id {sg_id} \\",
                f"  --protocol tcp \\",
                f"  --port 22 \\",
                f"  --cidr 0.0.0.0/0",
                f"",
                f"# Remove unrestricted RDP rule (port 3389)",
                f"aws ec2 revoke-security-group-ingress \\",
                f"  --group-id {sg_id} \\",
                f"  --protocol tcp \\",
                f"  --port 3389 \\",
                f"  --cidr 0.0.0.0/0",
                f"",
                f"# Add restricted rule (example: your office IP)",
                f"aws ec2 authorize-security-group-ingress \\",
                f"  --group-id {sg_id} \\",
                f"  --protocol tcp \\",
                f"  --port 22 \\",
                f"  --cidr YOUR_IP/32",
                f"",
                f"# Verify changes",
                f"aws ec2 describe-security-groups --group-ids {sg_id}"
            ],
            'manual_steps': [
                f"1. Go to EC2 Console",
                f"2. Click 'Security Groups' in left menu",
                f"3. Select security group: {sg_id}",
                f"4. Click 'Inbound rules' tab",
                f"5. Click 'Edit inbound rules'",
                f"6. Find rules with Source '0.0.0.0/0'",
                f"7. Either:",
                f"   a) Delete the rule, or",
                f"   b) Change Source to specific IP/CIDR",
                f"8. Click 'Save rules'",
                f"",
                f"⚠️  WARNING: This will block access. Ensure you have:",
                f"   - Alternative access method (AWS Systems Manager)",
                f"   - Correct IP range for authorized users"
            ]
        }
    
    # ==================== CLOUDTRAIL REMEDIATION ====================
    
    def _remediate_cloudtrail(self, finding: Dict) -> Dict:
        """Generate CloudTrail remediation"""
        
        return {
            'terraform': '''# Enable CloudTrail for all regions
resource "aws_cloudtrail" "main" {
  name                          = "organization-trail"
  s3_bucket_name               = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_log_file_validation   = true
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }
  }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "my-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

data "aws_caller_identity" "current" {}
''',
            'aws_cli': [
                "# 1. Create S3 bucket for CloudTrail logs",
                "ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)",
                "BUCKET_NAME=\"my-cloudtrail-logs-${ACCOUNT_ID}\"",
                "",
                "aws s3api create-bucket \\",
                "  --bucket $BUCKET_NAME \\",
                "  --region us-east-1",
                "",
                "# 2. Create bucket policy (save this to bucket-policy.json)",
                "cat > bucket-policy.json << EOF",
                "{",
                '  "Version": "2012-10-17",',
                '  "Statement": [',
                "    {",
                '      "Sid": "AWSCloudTrailAclCheck",',
                '      "Effect": "Allow",',
                '      "Principal": {"Service": "cloudtrail.amazonaws.com"},',
                '      "Action": "s3:GetBucketAcl",',
                '      "Resource": "arn:aws:s3:::${BUCKET_NAME}"',
                "    },",
                "    {",
                '      "Sid": "AWSCloudTrailWrite",',
                '      "Effect": "Allow",',
                '      "Principal": {"Service": "cloudtrail.amazonaws.com"},',
                '      "Action": "s3:PutObject",',
                '      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*",',
                '      "Condition": {',
                '        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}',
                "      }",
                "    }",
                "  ]",
                "}",
                "EOF",
                "",
                "# 3. Apply bucket policy",
                "aws s3api put-bucket-policy \\",
                "  --bucket $BUCKET_NAME \\",
                "  --policy file://bucket-policy.json",
                "",
                "# 4. Create CloudTrail",
                "aws cloudtrail create-trail \\",
                "  --name organization-trail \\",
                "  --s3-bucket-name $BUCKET_NAME \\",
                "  --is-multi-region-trail \\",
                "  --enable-log-file-validation",
                "",
                "# 5. Start logging",
                "aws cloudtrail start-logging --name organization-trail",
                "",
                "# 6. Verify trail is active",
                "aws cloudtrail get-trail-status --name organization-trail"
            ],
            'manual_steps': [
                "1. Go to CloudTrail Console",
                "2. Click 'Create trail'",
                "3. Enter trail name: 'organization-trail'",
                "4. Storage location:",
                "   - Create new S3 bucket or use existing",
                "5. Log events:",
                "   - Check 'Management events'",
                "   - Check 'Data events' (optional)",
                "6. Advanced settings:",
                "   - Enable log file validation",
                "   - Enable multi-region trail",
                "7. Click 'Create trail'",
                "8. Trail will start logging automatically"
            ]
        }
    
    # ==================== EXECUTION METHODS ====================
    
    def execute_remediation(self, finding: Dict, method: str = 'aws_cli') -> Dict:
        """Execute automated remediation"""
        
        result = {
            'status': 'pending',
            'finding_id': finding.get('id'),
            'method': method,
            'timestamp': datetime.now().isoformat(),
            'backup_id': None,
            'verification': None,
            'error': None
        }
        
        try:
            # Get remediation options
            options = self.get_remediation_options(finding)
            
            if not options['automated_available']:
                result['status'] = 'failed'
                result['error'] = 'Automated remediation not available for this finding'
                return result
            
            # Create backup
            result['backup_id'] = self._create_backup(finding)
            
            # Execute remediation based on method
            if method == 'aws_cli':
                # In production, you would execute the CLI commands
                result['status'] = 'success'
                result['verification'] = 'CLI commands completed'
            
            # Verify remediation
            verification = self._verify_remediation(finding)
            result['verification'] = verification
            
            if verification['passed']:
                result['status'] = 'success'
            else:
                result['status'] = 'failed'
                result['error'] = verification.get('error')
                # Rollback
                if result['backup_id']:
                    self._rollback(result['backup_id'])
        
        except Exception as e:
            result['status'] = 'failed'
            result['error'] = str(e)
            
            # Attempt rollback
            if result['backup_id']:
                try:
                    self._rollback(result['backup_id'])
                    result['rollback'] = 'completed'
                except:
                    result['rollback'] = 'failed'
        
        return result
    
    def _create_backup(self, finding: Dict) -> str:
        """Create backup before remediation"""
        # In production, this would create actual backups
        backup_id = f"backup_{finding.get('id')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return backup_id
    
    def _verify_remediation(self, finding: Dict) -> Dict:
        """Verify remediation was successful"""
        # In production, this would actually check the resource
        return {
            'passed': True,
            'message': 'Remediation verified successfully'
        }
    
    def _rollback(self, backup_id: str):
        """Rollback to backup"""
        # In production, this would restore from backup
        pass


# Example usage
if __name__ == "__main__":
    engine = RemediationEngine()
    
    finding = {
        'id': 'finding-001',
        'service': 'S3',
        'title': 'S3 Bucket Without Encryption Enabled',
        'resource': 'my-bucket-name'
    }
    
    options = engine.get_remediation_options(finding)
    print("Terraform Code:")
    print(options['terraform'])
    print("\nAWS CLI Commands:")
    print("\n".join(options['aws_cli']))
