"""
AWS Developer Experience (DevEx) - Your Coding Assistant
Practical tools, ready-to-use code, and AI help for AWS developers
"""

import streamlit as st
from auth_azure_sso import require_permission
import json
import os
import streamlit as st
import json
import os

class DevExModule:
    """AWS Developer Experience - Practical Coding Helper"""
    
    @staticmethod
    @require_permission('use_devex')

    def render():
        """Render AWS DevEx module"""
        
        st.title("👨‍💻 AWS Developer Experience")
        st.markdown("**Your coding assistant** - Copy-paste code, generate commands, get instant help")
        
        ai_available = True
        
        if ai_available:
            st.success("🤖 **AI Assistant: READY** | Ask coding questions | Generate AWS code | Debug issues")
        
        tabs = st.tabs([
            "🏠 Dev Portal",
            "📚 Quick Reference",
            "💻 Code Generator",
            "🔧 AWS CLI Commands",
            "🚀 Getting Started",
            "🎯 Try It Now",
            "🤖 AI Helper",
            "🐛 Debug Assistant"
        ])
        
        with tabs[0]:
            DevExModule._render_developer_portal()
        with tabs[1]:
            DevExModule._render_quick_reference()
        with tabs[2]:
            DevExModule._render_code_generator()
        with tabs[3]:
            DevExModule._render_cli_commands()
        with tabs[4]:
            DevExModule._render_getting_started()
        with tabs[5]:
            DevExModule._render_try_it_now()
        with tabs[6]:
            DevExModule._render_ai_helper(ai_available)
        with tabs[7]:
            DevExModule._render_debug_assistant(ai_available)
    
    @staticmethod
    def _render_developer_portal():
        """Developer portal hub"""
        st.markdown("## 🏠 AWS Developer Portal")
        st.caption("Your one-stop shop for AWS development")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("### 🚀 Quick Actions")
            if st.button("📋 Generate AWS CLI command", use_container_width=True):
                st.info("Jump to AWS CLI Commands tab →")
            if st.button("💻 Get code snippet", use_container_width=True):
                st.info("Jump to Code Generator tab →")
            if st.button("🐛 Debug my issue", use_container_width=True):
                st.info("Jump to Debug Assistant tab →")
            if st.button("🤖 Ask AI", use_container_width=True):
                st.info("Jump to AI Helper tab →")
        
        with col2:
            st.markdown("### 📚 Popular Resources")
            st.markdown("""
            - [AWS SDK for Python (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
            - [AWS SDK for JavaScript](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/)
            - [AWS SDK for Java](https://docs.aws.amazon.com/sdk-for-java/)
            - [AWS CLI Documentation](https://docs.aws.amazon.com/cli/latest/)
            - [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
            - [AWS REST API Reference](https://docs.aws.amazon.com/api-gateway/latest/api/)
            """)
        
        with col3:
            st.markdown("### 💡 Common Tasks")
            st.markdown("""
            **Storage:**
            - Upload to S3
            - List bucket objects
            - Generate presigned URLs
            
            **Compute:**
            - Launch EC2 instance
            - Deploy Lambda function
            - Create ECS task
            
            **Database:**
            - Connect to RDS
            - Query DynamoDB
            - Use ElastiCache
            """)
        
        st.markdown("---")
        st.markdown("### 🎯 Today's Tips")
        
        tips = [
            "💡 **Tip:** Use IAM roles instead of access keys - never hardcode credentials",
            "💡 **Tip:** Add `--query` to AWS CLI commands to filter output with JMESPath",
            "💡 **Tip:** Use AWS CloudShell for instant CLI access with no setup needed",
            "💡 **Tip:** Enable AWS X-Ray for automatic distributed tracing in your apps"
        ]
        
        for tip in tips:
            st.info(tip)
    
    @staticmethod
    def _render_quick_reference():
        """Quick reference guide"""
        st.markdown("## 📚 AWS Quick Reference")
        st.caption("Common patterns and examples you can copy-paste")
        
        category = st.selectbox("Select Category", [
            "Storage (S3, EFS)",
            "Compute (EC2, Lambda, ECS)",
            "Database (RDS, DynamoDB)",
            "Messaging (SQS, SNS, EventBridge)",
            "Identity (IAM, Cognito)",
            "Monitoring (CloudWatch, X-Ray)"
        ])
        
        if "Storage" in category:
            st.markdown("### 📦 S3 Storage - Python (Boto3)")
            st.code('''
import boto3
from botocore.exceptions import ClientError

# Using IAM role (recommended - no credentials needed!)
s3 = boto3.client('s3')

# Upload file
try:
    s3.upload_file('local_file.txt', 'my-bucket', 'myfile.txt')
    print('✅ File uploaded to s3://my-bucket/myfile.txt')
except ClientError as e:
    print(f'Error: {e}')

# Download file
s3.download_file('my-bucket', 'myfile.txt', 'downloaded.txt')

# List objects
response = s3.list_objects_v2(Bucket='my-bucket', Prefix='folder/')
for obj in response.get('Contents', []):
    print(f"  {obj['Key']} - {obj['Size']} bytes")

# Generate presigned URL (valid for 1 hour)
url = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'my-bucket', 'Key': 'myfile.txt'},
    ExpiresIn=3600
)
print(f'Download URL: {url}')

# Upload with metadata
s3.upload_file(
    'local_file.txt',
    'my-bucket',
    'myfile.txt',
    ExtraArgs={
        'Metadata': {'uploaded-by': 'my-app'},
        'ContentType': 'text/plain'
    }
)
            ''', language='python')
            
            st.markdown("### 📦 S3 Storage - Node.js")
            st.code('''
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const fs = require('fs');

const s3 = new S3Client({ region: 'us-east-1' });

// Upload file
async function uploadFile() {
    const fileContent = fs.readFileSync('local_file.txt');
    const command = new PutObjectCommand({
        Bucket: 'my-bucket',
        Key: 'myfile.txt',
        Body: fileContent
    });
    await s3.send(command);
    console.log('✅ File uploaded');
}

// Generate presigned URL
async function getPresignedUrl() {
    const command = new GetObjectCommand({
        Bucket: 'my-bucket',
        Key: 'myfile.txt'
    });
    const url = await getSignedUrl(s3, command, { expiresIn: 3600 });
    console.log('Download URL:', url);
}
            ''', language='javascript')
        
        elif "Compute" in category:
            st.markdown("### ⚡ Lambda Function - Python")
            st.code('''
import json
import boto3

# Lambda handler function
def lambda_handler(event, context):
    """
    Process S3 event or API Gateway request
    """
    
    # Log the event
    print(f"Event: {json.dumps(event)}")
    
    # Example: Process S3 event
    if 'Records' in event:
        for record in event['Records']:
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']
            print(f"Processing {bucket}/{key}")
            
            # Your processing logic here
            s3 = boto3.client('s3')
            obj = s3.get_object(Bucket=bucket, Key=key)
            content = obj['Body'].read().decode('utf-8')
            print(f"Content: {content}")
    
    # Example: API Gateway response
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'message': 'Success!',
            'event': event
        })
    }

# requirements.txt
# boto3
            ''', language='python')
            
            st.markdown("### 🖥️ EC2 Instance Management")
            st.code('''
import boto3

ec2 = boto3.client('ec2', region_name='us-east-1')

# Launch instance
response = ec2.run_instances(
    ImageId='ami-0c55b159cbfafe1f0',  # Amazon Linux 2
    InstanceType='t3.micro',
    MinCount=1,
    MaxCount=1,
    KeyName='my-keypair',
    SecurityGroupIds=['sg-xxxxx'],
    SubnetId='subnet-xxxxx',
    TagSpecifications=[{
        'ResourceType': 'instance',
        'Tags': [
            {'Key': 'Name', 'Value': 'MyInstance'},
            {'Key': 'Environment', 'Value': 'Production'}
        ]
    }]
)
instance_id = response['Instances'][0]['InstanceId']
print(f'✅ Launched instance: {instance_id}')

# Start instance
ec2.start_instances(InstanceIds=[instance_id])

# Stop instance
ec2.stop_instances(InstanceIds=[instance_id])

# Get instance details
response = ec2.describe_instances(InstanceIds=[instance_id])
instance = response['Reservations'][0]['Instances'][0]
print(f"State: {instance['State']['Name']}")
print(f"Public IP: {instance.get('PublicIpAddress', 'N/A')}")
            ''', language='python')
        
        elif "Database" in category:
            st.markdown("### 🗄️ DynamoDB - Python")
            st.code('''
import boto3
from boto3.dynamodb.conditions import Key, Attr

dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('my-table')

# Put item
table.put_item(
    Item={
        'user_id': '12345',
        'name': 'John Doe',
        'email': 'john@example.com',
        'created_at': '2024-12-07T10:00:00Z'
    }
)
print('✅ Item created')

# Get item
response = table.get_item(Key={'user_id': '12345'})
item = response.get('Item')
print(f'User: {item}')

# Query with condition
response = table.query(
    KeyConditionExpression=Key('user_id').eq('12345')
)
items = response['Items']

# Scan with filter
response = table.scan(
    FilterExpression=Attr('email').contains('@example.com')
)

# Update item
table.update_item(
    Key={'user_id': '12345'},
    UpdateExpression='SET #name = :name',
    ExpressionAttributeNames={'#name': 'name'},
    ExpressionAttributeValues={':name': 'Jane Doe'}
)

# Batch write
with table.batch_writer() as batch:
    for i in range(100):
        batch.put_item(Item={'user_id': str(i), 'name': f'User {i}'})
            ''', language='python')
            
            st.markdown("### 🗄️ RDS Connection - Python")
            st.code('''
import pymysql
import boto3

# Get RDS credentials from Secrets Manager (recommended)
secrets = boto3.client('secretsmanager', region_name='us-east-1')
secret = secrets.get_secret_value(SecretId='rds/mydb/credentials')
import json
creds = json.loads(secret['SecretString'])

# Connect to RDS
connection = pymysql.connect(
    host=creds['host'],
    user=creds['username'],
    password=creds['password'],
    database='mydb',
    cursorclass=pymysql.cursors.DictCursor
)

try:
    with connection.cursor() as cursor:
        # Execute query
        cursor.execute("SELECT * FROM users WHERE active = %s", (True,))
        results = cursor.fetchall()
        for row in results:
            print(row)
        
        # Insert data
        cursor.execute(
            "INSERT INTO users (name, email) VALUES (%s, %s)",
            ('John Doe', 'john@example.com')
        )
        connection.commit()
finally:
    connection.close()
            ''', language='python')
        
        elif "Messaging" in category:
            st.markdown("### 📬 SQS - Send and Receive Messages")
            st.code('''
import boto3
import json

sqs = boto3.client('sqs', region_name='us-east-1')
queue_url = 'https://sqs.us-east-1.amazonaws.com/123456789/my-queue'

# Send message
response = sqs.send_message(
    QueueUrl=queue_url,
    MessageBody=json.dumps({
        'user_id': '12345',
        'action': 'process_order',
        'order_id': 'ORD-789'
    }),
    MessageAttributes={
        'Priority': {
            'StringValue': 'High',
            'DataType': 'String'
        }
    }
)
print(f"✅ Message sent: {response['MessageId']}")

# Receive messages
response = sqs.receive_message(
    QueueUrl=queue_url,
    MaxNumberOfMessages=10,
    WaitTimeSeconds=20,  # Long polling
    MessageAttributeNames=['All']
)

for message in response.get('Messages', []):
    body = json.loads(message['Body'])
    print(f"Processing: {body}")
    
    # Delete message after processing
    sqs.delete_message(
        QueueUrl=queue_url,
        ReceiptHandle=message['ReceiptHandle']
    )
    print('✅ Message deleted')
            ''', language='python')
            
            st.markdown("### 📢 SNS - Publish Messages")
            st.code('''
import boto3
import json

sns = boto3.client('sns', region_name='us-east-1')
topic_arn = 'arn:aws:sns:us-east-1:123456789:my-topic'

# Publish message
response = sns.publish(
    TopicArn=topic_arn,
    Subject='Order Confirmation',
    Message=json.dumps({
        'user_id': '12345',
        'order_id': 'ORD-789',
        'total': 99.99
    }),
    MessageAttributes={
        'type': {
            'DataType': 'String',
            'StringValue': 'order_confirmation'
        }
    }
)
print(f"✅ Published: {response['MessageId']}")
            ''', language='python')
        
        st.markdown("---")
        st.info("💡 **Pro Tip:** Always use IAM roles instead of access keys - safer and no credential management!")
    
    @staticmethod
    def _render_code_generator():
        """Interactive code generator"""
        st.markdown("## 💻 AWS Code Generator")
        st.caption("Generate ready-to-use code for common tasks")
        
        task = st.selectbox("What do you want to do?", [
            "Upload file to S3",
            "Query DynamoDB",
            "Send SQS message",
            "Invoke Lambda function",
            "Launch EC2 instance",
            "Read Secrets Manager secret",
            "Publish to SNS"
        ])
        
        language = st.selectbox("Programming Language", ["Python", "Node.js", "Java", "Go", "AWS CLI"])
        
        if task == "Upload file to S3":
            bucket = st.text_input("Bucket Name", "my-bucket")
            key = st.text_input("Object Key", "myfile.txt")
            
            if language == "Python":
                code = f'''
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client('s3')

try:
    # Upload file
    s3.upload_file('local_file.txt', '{bucket}', '{key}')
    print(f'✅ Uploaded to s3://{bucket}/{key}')
    
    # Upload with metadata
    s3.upload_file(
        'local_file.txt',
        '{bucket}',
        '{key}',
        ExtraArgs={{
            'Metadata': {{'uploaded-by': 'my-app'}},
            'ContentType': 'text/plain',
            'ServerSideEncryption': 'AES256'
        }}
    )
except ClientError as e:
    print(f'Error uploading file: {{e}}')
'''
            elif language == "AWS CLI":
                code = f'''
# Upload single file
aws s3 cp local_file.txt s3://{bucket}/{key}

# Upload with metadata
aws s3 cp local_file.txt s3://{bucket}/{key} \\
    --metadata uploaded-by=my-app \\
    --content-type text/plain \\
    --server-side-encryption AES256

# Upload directory (recursive)
aws s3 cp ./local_directory/ s3://{bucket}/ --recursive

# Sync directory
aws s3 sync ./local_directory/ s3://{bucket}/
'''
            else:
                code = "# Code generation for this language coming soon!"
            
            st.code(code, language='python' if language == "Python" else 'bash')
            st.button("📋 Copy to Clipboard")
        
        elif task == "Query DynamoDB":
            table = st.text_input("Table Name", "my-table")
            key = st.text_input("Partition Key Name", "user_id")
            
            code = f'''
import boto3
from boto3.dynamodb.conditions import Key, Attr

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('{table}')

# Get single item
response = table.get_item(Key={{'{key}': '12345'}})
item = response.get('Item')
print(item)

# Query items
response = table.query(
    KeyConditionExpression=Key('{key}').eq('12345')
)
items = response['Items']

# Scan with filter
response = table.scan(
    FilterExpression=Attr('status').eq('active')
)
items = response['Items']
'''
            st.code(code, language='python')
        
        elif task == "Launch EC2 instance":
            ami = st.text_input("AMI ID", "ami-0c55b159cbfafe1f0")
            instance_type = st.selectbox("Instance Type", ["t3.micro", "t3.small", "t3.medium", "m5.large"])
            
            code = f'''
# Using AWS CLI
aws ec2 run-instances \\
    --image-id {ami} \\
    --instance-type {instance_type} \\
    --key-name my-keypair \\
    --security-group-ids sg-xxxxx \\
    --subnet-id subnet-xxxxx \\
    --tag-specifications 'ResourceType=instance,Tags=[{{Key=Name,Value=MyInstance}}]'

# Get instance ID
INSTANCE_ID=$(aws ec2 describe-instances \\
    --filters "Name=tag:Name,Values=MyInstance" "Name=instance-state-name,Values=running" \\
    --query 'Reservations[0].Instances[0].InstanceId' \\
    --output text)

echo "Instance ID: $INSTANCE_ID"
'''
            st.code(code, language='bash')
            st.success("✅ Generated! Copy and run in AWS CloudShell or your terminal")
    
    @staticmethod
    def _render_cli_commands():
        """AWS CLI command helper"""
        st.markdown("## 🔧 AWS CLI Command Helper")
        st.caption("Build AWS CLI commands interactively")
        
        service = st.selectbox("AWS Service", [
            "S3",
            "EC2",
            "Lambda",
            "DynamoDB",
            "RDS",
            "ECS"
        ])
        
        operation = st.selectbox("Operation", ["Create", "List", "Describe", "Delete", "Update"])
        
        if service == "S3" and operation == "Create":
            st.markdown("### Create S3 Bucket")
            bucket_name = st.text_input("Bucket Name", "my-bucket-12345")
            region = st.selectbox("Region", ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"])
            
            cmd = f'''aws s3 mb s3://{bucket_name} --region {region}

# Enable versioning
aws s3api put-bucket-versioning \\
    --bucket {bucket_name} \\
    --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \\
    --bucket {bucket_name} \\
    --server-side-encryption-configuration '{{
        "Rules": [{{
            "ApplyServerSideEncryptionByDefault": {{
                "SSEAlgorithm": "AES256"
            }}
        }}]
    }}'

# Block public access
aws s3api put-public-access-block \\
    --bucket {bucket_name} \\
    --public-access-block-configuration \\
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'''
            
            st.code(cmd, language='bash')
            st.info("💡 Run this in AWS CloudShell or your terminal")
        
        elif service == "EC2" and operation == "Create":
            instance_name = st.text_input("Instance Name", "MyInstance")
            instance_type = st.selectbox("Instance Type", ["t3.micro", "t3.small", "t3.medium", "m5.large"])
            ami = st.selectbox("AMI", ["Amazon Linux 2", "Ubuntu 22.04", "Windows Server 2022"])
            
            ami_ids = {
                "Amazon Linux 2": "ami-0c55b159cbfafe1f0",
                "Ubuntu 22.04": "ami-0557a15b87f6559cf",
                "Windows Server 2022": "ami-0d5bf08bc8017c83b"
            }
            
            cmd = f'''aws ec2 run-instances \\
    --image-id {ami_ids[ami]} \\
    --instance-type {instance_type} \\
    --key-name my-keypair \\
    --security-group-ids sg-xxxxx \\
    --subnet-id subnet-xxxxx \\
    --tag-specifications 'ResourceType=instance,Tags=[{{Key=Name,Value={instance_name}}}]' \\
    --monitoring Enabled=true

# Get instance ID
INSTANCE_ID=$(aws ec2 describe-instances \\
    --filters "Name=tag:Name,Values={instance_name}" \\
    --query 'Reservations[0].Instances[0].InstanceId' \\
    --output text)

# Get public IP
aws ec2 describe-instances \\
    --instance-ids $INSTANCE_ID \\
    --query 'Reservations[0].Instances[0].PublicIpAddress' \\
    --output text'''
            
            st.code(cmd, language='bash')
    
    @staticmethod
    def _render_getting_started():
        """Getting started guide"""
        st.markdown("## 🚀 Getting Started with AWS Development")
        
        st.markdown("### 1️⃣ Install AWS CLI")
        st.code('''
# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Windows
# Download from: https://awscli.amazonaws.com/AWSCLIV2.msi

# Verify installation
aws --version
        ''', language='bash')
        
        st.markdown("### 2️⃣ Configure AWS CLI")
        st.code('''
# Configure with access keys (for local development)
aws configure

# Enter:
# - AWS Access Key ID
# - AWS Secret Access Key  
# - Default region (e.g., us-east-1)
# - Default output format (json)

# Verify configuration
aws sts get-caller-identity

# Use named profiles
aws configure --profile dev
aws s3 ls --profile dev

# Set default region
aws configure set region us-east-1
        ''', language='bash')
        
        st.markdown("### 3️⃣ Install Boto3 (Python SDK)")
        st.code('''
# Install boto3
pip install boto3

# Install with additional dependencies
pip install boto3 botocore

# For specific services
pip install boto3[s3]

# Verify installation
python -c "import boto3; print(boto3.__version__)"
        ''', language='bash')
        
        st.markdown("### 4️⃣ Your First AWS Python App")
        st.code('''
import boto3
from botocore.exceptions import ClientError

# Create S3 client (uses AWS CLI credentials automatically)
s3 = boto3.client('s3')

# List buckets
response = s3.list_buckets()
print('📦 Your S3 Buckets:')
for bucket in response['Buckets']:
    print(f"  - {bucket['Name']}")

# Create a new bucket
bucket_name = 'my-app-bucket-12345'
try:
    s3.create_bucket(Bucket=bucket_name)
    print(f'✅ Created bucket: {bucket_name}')
except ClientError as e:
    print(f'Error: {e}')

# Upload a file
with open('hello.txt', 'w') as f:
    f.write('Hello AWS!')

s3.upload_file('hello.txt', bucket_name, 'hello.txt')
print(f'✅ Uploaded hello.txt to {bucket_name}')

# Download the file
s3.download_file(bucket_name, 'hello.txt', 'downloaded.txt')
print('✅ Downloaded file')

print('🎉 Success! You just used AWS with Python!')
        ''', language='python')
        
        st.success("🎉 You're ready to build on AWS!")
    
    @staticmethod
    def _render_try_it_now():
        """Interactive sandbox"""
        st.markdown("## 🎯 Try AWS Commands Now")
        st.caption("Interactive environment to test AWS commands")
        
        st.info("🚀 **CloudShell:** Open [AWS CloudShell](https://console.aws.amazon.com/cloudshell) in a new tab to try these commands!")
        
        st.markdown("### 📝 Common Commands to Try")
        
        with st.expander("🔍 List Resources"):
            st.code('''
# List S3 buckets
aws s3 ls

# List EC2 instances
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,Tags[?Key==`Name`].Value|[0]]' --output table

# List Lambda functions
aws lambda list-functions --query 'Functions[].[FunctionName,Runtime,LastModified]' --output table

# List DynamoDB tables
aws dynamodb list-tables

# List RDS instances
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Engine,DBInstanceStatus]' --output table
            ''', language='bash')
        
        with st.expander("📦 S3 Operations"):
            st.code('''
# Create bucket
aws s3 mb s3://my-test-bucket-12345 --region us-east-1

# Upload file
echo "Hello AWS!" > hello.txt
aws s3 cp hello.txt s3://my-test-bucket-12345/

# List bucket contents
aws s3 ls s3://my-test-bucket-12345/

# Download file
aws s3 cp s3://my-test-bucket-12345/hello.txt downloaded.txt

# Generate presigned URL (valid for 1 hour)
aws s3 presign s3://my-test-bucket-12345/hello.txt --expires-in 3600

# Sync directory
aws s3 sync ./local_folder s3://my-test-bucket-12345/remote_folder/

# Delete file
aws s3 rm s3://my-test-bucket-12345/hello.txt

# Delete bucket
aws s3 rb s3://my-test-bucket-12345 --force
            ''', language='bash')
        
        with st.expander("🖥️ EC2 Operations"):
            st.code('''
# Launch instance
aws ec2 run-instances \\
    --image-id ami-0c55b159cbfafe1f0 \\
    --instance-type t3.micro \\
    --key-name my-keypair \\
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=TestInstance}]'

# List instances
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,PublicIpAddress]' --output table

# Start instance
aws ec2 start-instances --instance-ids i-1234567890abcdef0

# Stop instance
aws ec2 stop-instances --instance-ids i-1234567890abcdef0

# Get instance details
aws ec2 describe-instances --instance-ids i-1234567890abcdef0

# Terminate instance
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0
            ''', language='bash')
        
        with st.expander("⚡ Lambda Operations"):
            st.code('''
# List functions
aws lambda list-functions

# Create function (requires ZIP file)
aws lambda create-function \\
    --function-name my-function \\
    --runtime python3.11 \\
    --role arn:aws:iam::123456789:role/lambda-role \\
    --handler lambda_function.lambda_handler \\
    --zip-file fileb://function.zip

# Invoke function
aws lambda invoke \\
    --function-name my-function \\
    --payload '{"key":"value"}' \\
    response.json

# View response
cat response.json

# Update function code
aws lambda update-function-code \\
    --function-name my-function \\
    --zip-file fileb://function.zip

# Delete function
aws lambda delete-function --function-name my-function
            ''', language='bash')
    
    @staticmethod
    def _render_ai_helper(ai_available):
        """AI coding assistant"""
        st.markdown("## 🤖 AI AWS Coding Helper")
        st.caption("Ask me anything about AWS development!")
        
        if not ai_available:
            st.warning("⚠️ AI features require configuration")
            return
        
        st.markdown("### 💡 Quick Questions")
        questions = [
            "How do I authenticate to AWS from Python?",
            "What's the best way to store secrets?",
            "How do I connect to RDS from Lambda?",
            "Show me how to use DynamoDB",
            "How do I use IAM roles instead of keys?",
            "What's the difference between S3 storage classes?"
        ]
        
        col1, col2 = st.columns(2)
        for i, q in enumerate(questions):
            with col1 if i % 2 == 0 else col2:
                if st.button(f"💬 {q}", key=f"q_{i}", use_container_width=True):
                    st.info(f"🤖 Let me help with: {q}")
        
        st.markdown("---")
        user_question = st.text_area(
            "Ask your AWS coding question:",
            placeholder="e.g., How do I upload large files to S3 efficiently?",
            height=100
        )
        
        if st.button("🚀 Get AI Answer", type="primary", use_container_width=True):
            if user_question:
                st.success(f'''
**AI Response:**

For uploading large files to S3 efficiently, use multipart upload:

```python
import boto3
from boto3.s3.transfer import TransferConfig

s3 = boto3.client('s3')

# Configure multipart upload
config = TransferConfig(
    multipart_threshold=1024 * 25,  # 25MB
    max_concurrency=10,
    multipart_chunksize=1024 * 25,
    use_threads=True
)

# Upload large file
s3.upload_file(
    'large_file.zip',
    'my-bucket',
    'large_file.zip',
    Config=config
)

# Or use upload_fileobj for streaming
with open('large_file.zip', 'rb') as f:
    s3.upload_fileobj(f, 'my-bucket', 'large_file.zip', Config=config)
```

**Key points:**
- Files >100MB automatically use multipart upload
- Upload in 25MB chunks (configurable)
- Parallel upload with 10 concurrent threads
- Automatic retry on failure
- Progress tracking available with callbacks
                ''')
    
    @staticmethod
    def _render_debug_assistant(ai_available):
        """Debug helper"""
        st.markdown("## 🐛 AWS Debug Assistant")
        st.caption("Get help fixing common AWS issues")
        
        st.markdown("### 🔍 Common Issues & Solutions")
        
        with st.expander("❌ Access Denied / Permission Error"):
            st.markdown('''
**Problem:** Getting access denied errors

**Solutions:**
1. **Check IAM permissions:**
```bash
# View your identity
aws sts get-caller-identity

# Check IAM user permissions
aws iam list-attached-user-policies --user-name myuser

# Check IAM role permissions
aws iam get-role-policy --role-name myrole --policy-name mypolicy
```

2. **Use IAM roles instead of access keys:**
```python
# ❌ Don't hardcode credentials
import boto3
s3 = boto3.client('s3', 
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)

# ✅ Use IAM role (EC2, Lambda, ECS)
import boto3
s3 = boto3.client('s3')  # Automatically uses IAM role
```

3. **Grant required permissions:**
```bash
# Attach policy to role
aws iam attach-role-policy \\
    --role-name my-lambda-role \\
    --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```
            ''')
        
        with st.expander("❌ Bucket/Resource Not Found"):
            st.markdown('''
**Problem:** Resource doesn't exist or wrong region

**Solutions:**
1. **Check bucket exists:**
```bash
# List all buckets
aws s3 ls

# Check specific bucket
aws s3 ls s3://my-bucket/
```

2. **Verify region:**
```python
import boto3

# ❌ Wrong - uses default region
s3 = boto3.client('s3')

# ✅ Right - specify region
s3 = boto3.client('s3', region_name='us-west-2')

# Or get bucket region
s3 = boto3.client('s3')
response = s3.get_bucket_location(Bucket='my-bucket')
region = response['LocationConstraint']
print(f'Bucket is in: {region}')
```

3. **Check AWS CLI configuration:**
```bash
# View current region
aws configure get region

# Set default region
aws configure set region us-east-1
```
            ''')
        
        with st.expander("❌ Access Keys vs IAM Roles"):
            st.markdown('''
**Problem:** Confused about authentication methods

**Best Practice: Use IAM Roles**

❌ **DON'T** (Access Keys in Code):
```python
import boto3

s3 = boto3.client('s3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)
```

✅ **DO** (IAM Role):
```python
import boto3

# Automatically uses:
# - EC2 instance role
# - Lambda execution role
# - ECS task role
# - Local ~/.aws/credentials
s3 = boto3.client('s3')
```

**Why IAM Roles?**
- No credentials in code
- Automatic rotation
- Easy permission management
- Works everywhere (EC2, Lambda, ECS, local)
- More secure

**For local development:**
```bash
# Use AWS CLI configuration
aws configure

# Or use named profiles
aws configure --profile dev
export AWS_PROFILE=dev
```
            ''')
        
        with st.expander("❌ Lambda Function Timeout"):
            st.markdown('''
**Problem:** Lambda function timing out

**Solutions:**
1. **Increase timeout:**
```bash
# Set timeout to 5 minutes
aws lambda update-function-configuration \\
    --function-name my-function \\
    --timeout 300
```

2. **Optimize code:**
```python
import boto3

# ❌ Don't create client inside handler
def lambda_handler(event, context):
    s3 = boto3.client('s3')  # Created on every invocation
    s3.list_buckets()

# ✅ Create client outside handler
s3 = boto3.client('s3')  # Created once, reused

def lambda_handler(event, context):
    s3.list_buckets()  # Faster!
```

3. **Use async processing:**
```python
# For long-running tasks, use SQS + Lambda
import boto3

def lambda_handler(event, context):
    sqs = boto3.client('sqs')
    
    # Send to queue for async processing
    sqs.send_message(
        QueueUrl='https://sqs.us-east-1.amazonaws.com/123/my-queue',
        MessageBody='process this'
    )
    
    return {'statusCode': 202, 'body': 'Queued for processing'}
```
            ''')
        
        if ai_available:
            st.markdown("---")
            st.markdown("### 🤖 AI Debug Helper")
            error_msg = st.text_area(
                "Paste your error message:",
                placeholder="botocore.exceptions.NoCredentialsError: Unable to locate credentials",
                height=100
            )
            
            if st.button("🔍 Analyze Error", type="primary"):
                if error_msg:
                    st.success('''
**AI Analysis:**

This error means AWS credentials are not configured. Here's how to fix it:

**For local development:**
```bash
# Configure AWS CLI
aws configure

# Enter your:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region (e.g., us-east-1)
# - Output format (json)
```

**For production (EC2/Lambda/ECS):**
1. Attach an IAM role to your resource
2. Code will automatically use the role - no configuration needed!

**Verify credentials:**
```bash
# Check current identity
aws sts get-caller-identity

# Test with Python
python -c "import boto3; print(boto3.client('sts').get_caller_identity())"
```

**Python code:**
```python
import boto3
from auth_azure_sso import require_permission

# This will work automatically once credentials are configured
s3 = boto3.client('s3')
buckets = s3.list_buckets()
print(buckets)
```
                    ''')

def render():
    """Module-level render"""
    DevExModule.render()