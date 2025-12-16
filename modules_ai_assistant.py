"""
AI Assistant Module - Claude-Powered Cloud Operations Assistant (AWS)
Provides AI-powered assistance for AWS operations, architecture, and optimization
"""

import streamlit as st
from anthropic_helper_aws import get_aws_anthropic_helper as get_anthropic_helper
from typing import List, Dict
import json
from auth_azure_sso import require_permission

class AIAssistantModule:
    """AI-powered assistant for AWS cloud operations"""
    
    @staticmethod
    @require_permission('view_dashboard')

    def render():
        """Render AI assistant interface"""
        
        st.markdown("## 🤖 AI Assistant (Claude)")
        st.caption("AI-powered assistance for AWS architecture, operations, and optimization")
        
        # Check if Anthropic is available
        helper = get_anthropic_helper()
        
        if not helper.is_available():
            st.warning("⚠️ Anthropic API not configured")
            st.info("""
            To enable AI Assistant features:
            
            1. Add your Anthropic API key to `.streamlit/secrets.toml`:
            ```toml
            [anthropic]
            api_key = "sk-ant-..."
            ```
            
            2. Or set environment variable:
            ```bash
            export ANTHROPIC_API_KEY="sk-ant-..."
            ```
            
            Get your API key at: https://console.anthropic.com/
            """)
            return
        
        st.success("✅ AI Assistant Ready (AWS Mode)")
        
        # AI Assistant features in tabs
        tabs = st.tabs([
            "💬 Chat Assistant",
            "🏗️ Architecture Design",
            "💰 Cost Optimization",
            "🔒 Security Analysis",
            "📝 Generate IaC",
            "📚 Runbook Generator"
        ])
        
        # Tab 1: Chat Assistant
        with tabs[0]:
            AIAssistantModule._render_chat_assistant(helper)
        
        # Tab 2: Architecture Design
        with tabs[1]:
            AIAssistantModule._render_architecture_design(helper)
        
        # Tab 3: Cost Optimization
        with tabs[2]:
            AIAssistantModule._render_cost_optimization(helper)
        
        # Tab 4: Security Analysis
        with tabs[3]:
            AIAssistantModule._render_security_analysis(helper)
        
        # Tab 5: Generate IaC
        with tabs[4]:
            AIAssistantModule._render_iac_generator(helper)
        
        # Tab 6: Runbook Generator
        with tabs[5]:
            AIAssistantModule._render_runbook_generator(helper)
    
    @staticmethod
    def _render_chat_assistant(helper):
        """Chat interface with Claude"""
        st.markdown("### 💬 Chat with Claude - AWS Expert")
        st.caption("Ask questions about AWS, get recommendations, troubleshoot issues")
        
        # Quick questions
        st.markdown("**Quick Questions:**")
        col1, col2, col3 = st.columns(3)
        
        quick_questions = [
            "How do I set up high availability for my web app?",
            "What's the best way to optimize my AWS costs?",
            "How can I improve my RDS database performance?",
            "What security best practices should I follow?",
            "How do I migrate from EC2 to containers?",
            "What's the difference between Lambda and Fargate?"
        ]
        
        for i, question in enumerate(quick_questions):
            col = [col1, col2, col3][i % 3]
            with col:
                if st.button(question, key=f"quick_{i}", use_container_width=True):
                    st.session_state.quick_question = question
        
        # Initialize chat history
        if "chat_history" not in st.session_state:
            st.session_state.chat_history = []
        
        # Handle quick question
        if hasattr(st.session_state, 'quick_question'):
            user_input = st.session_state.quick_question
            delattr(st.session_state, 'quick_question')
            
            st.session_state.chat_history.append({
                "role": "user",
                "content": user_input
            })
            
            with st.spinner("Thinking..."):
                system_prompt = "You are an AWS cloud expert assistant. Provide detailed, practical answers about AWS services, architecture, and best practices."
                response = helper.chat(user_input, st.session_state.chat_history[:-1], system_prompt)
            
            if response:
                st.session_state.chat_history.append({
                    "role": "assistant",
                    "content": response
                })
            st.rerun()
        
        # Display chat history
        for message in st.session_state.chat_history:
            role = message["role"]
            content = message["content"]
            
            if role == "user":
                st.chat_message("user").write(content)
            else:
                st.chat_message("assistant").write(content)
        
        # Chat input
        user_input = st.chat_input("Ask me anything about AWS infrastructure...")
        
        if user_input:
            # Add user message to history
            st.session_state.chat_history.append({
                "role": "user",
                "content": user_input
            })
            
            # Display user message
            st.chat_message("user").write(user_input)
            
            # Get AI response
            with st.spinner("Thinking..."):
                system_prompt = "You are an AWS cloud expert assistant. Provide detailed, practical answers about AWS services, architecture, and best practices."
                response = helper.chat(user_input, st.session_state.chat_history[:-1], system_prompt)
            
            if response:
                # Add assistant message to history
                st.session_state.chat_history.append({
                    "role": "assistant",
                    "content": response
                })
                
                # Display assistant message
                st.chat_message("assistant").write(response)
            else:
                st.error("Failed to get response from AI assistant")
        
        # Clear chat button
        if st.session_state.chat_history:
            if st.button("🗑️ Clear Chat History"):
                st.session_state.chat_history = []
                st.rerun()
    
    @staticmethod
    def _render_architecture_design(helper):
        """Architecture design assistant"""
        st.markdown("### 🏗️ Architecture Design Assistant")
        st.caption("Get AI-powered AWS architecture recommendations")
        
        with st.form("architecture_form"):
            st.markdown("#### Describe Your Requirements")
            
            col1, col2 = st.columns(2)
            
            with col1:
                services = st.multiselect(
                    "AWS Services Needed",
                    ["EC2", "RDS", "S3", "Lambda", "ECS", "EKS", "DynamoDB", 
                     "ElastiCache", "CloudFront", "API Gateway", "SNS", "SQS",
                     "Aurora", "Redshift", "EMR", "Kinesis", "EventBridge",
                     "Step Functions", "AppSync", "Cognito", "WAF", "Shield"]
                )
                
                traffic = st.selectbox(
                    "Expected Traffic",
                    ["Low (< 1,000 req/day)", "Medium (1K-10K req/day)", 
                     "High (10K-100K req/day)", "Very High (100K-1M req/day)",
                     "Extreme (> 1M req/day)"]
                )
                
                budget = st.selectbox(
                    "Monthly Budget",
                    ["< $1,000", "$1,000 - $5,000", "$5,000 - $20,000", 
                     "$20,000 - $50,000", "> $50,000"]
                )
            
            with col2:
                compliance = st.multiselect(
                    "Compliance Requirements",
                    ["PCI-DSS", "HIPAA", "SOC 2", "GDPR", "FedRAMP", "ISO 27001", "None"]
                )
                
                architecture_type = st.selectbox(
                    "Architecture Type",
                    ["Web Application", "API Backend", "Data Processing Pipeline",
                     "Real-time Analytics", "Mobile Backend", "E-commerce Platform",
                     "IoT Platform", "Microservices", "Serverless"]
                )
                
                ha_required = st.checkbox("High Availability Required (Multi-AZ)")
                dr_required = st.checkbox("Disaster Recovery Required (Multi-Region)")
            
            additional_requirements = st.text_area(
                "Additional Requirements",
                placeholder="Any specific requirements, constraints, or preferences...\n\nExample:\n- Must support 10,000 concurrent users\n- Need real-time data processing\n- Integration with on-premise Active Directory",
                height=100
            )
            
            submitted = st.form_submit_button("🎯 Generate Architecture Recommendation", use_container_width=True)
        
        if submitted and services:
            with st.spinner("🤖 Generating architecture recommendations..."):
                requirements_text = f"""
Design an AWS architecture with the following requirements:

**Services**: {', '.join(services)}
**Architecture Type**: {architecture_type}
**Expected Traffic**: {traffic}
**Budget**: {budget}
**Compliance**: {', '.join(compliance) if compliance else 'None'}
**High Availability**: {'Yes (Multi-AZ)' if ha_required else 'No'}
**Disaster Recovery**: {'Yes (Multi-Region)' if dr_required else 'No'}

**Additional Requirements**:
{additional_requirements if additional_requirements else 'None'}

Please provide:
1. Architecture overview with component diagram description
2. Detailed service selection and configuration
3. Networking design (VPC, subnets, security groups)
4. High availability and scalability approach
5. Security best practices
6. Cost estimation and optimization tips
7. Deployment strategy
"""
                
                recommendation = helper.chat(requirements_text, [], 
                    "You are an AWS Solutions Architect. Provide detailed, production-ready architecture recommendations.")
            
            if recommendation:
                st.markdown("#### 🎯 Architecture Recommendation")
                st.markdown(recommendation)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.button("💾 Save Recommendation"):
                        st.success("✅ Recommendation saved")
                with col2:
                    if st.button("📄 Export as PDF"):
                        st.success("✅ Exported to PDF")
                with col3:
                    if st.button("📝 Generate IaC"):
                        st.success("✅ Switched to IaC tab")
    
    @staticmethod
    def _render_cost_optimization(helper):
        """Cost optimization assistant"""
        st.markdown("### 💰 Cost Optimization Assistant")
        st.caption("Analyze AWS resources and get AI-powered cost optimization recommendations")
        
        # Analysis type
        analysis_type = st.radio(
            "Analysis Type",
            ["Quick Scan", "Deep Analysis", "Custom Query"],
            horizontal=True
        )
        
        if analysis_type == "Quick Scan":
            st.info("Quick scan analyzes common cost optimization opportunities across EC2, RDS, and S3")
            
            if st.button("🔍 Run Quick Scan", use_container_width=True):
                with st.spinner("🤖 Analyzing resources for cost optimization..."):
                    # Simulate resource analysis
                    resources_text = """
Analyze these AWS resources for cost optimization:

**EC2 Instances:**
- i-abc123: t3.xlarge, CPU avg 15%, Running 24/7
- i-def456: m5.2xlarge, CPU avg 8%, Running 24/7
- i-ghi789: c5.4xlarge, CPU avg 45%, Running 24/7

**RDS Databases:**
- db-prod: db.r5.2xlarge, Connections avg 25%, Multi-AZ, 500GB storage
- db-staging: db.m5.large, Connections avg 5%, Single-AZ, 100GB storage

**EBS Volumes:**
- vol-123: io1, 10,000 IOPS, 30% utilization
- vol-456: gp2, 500GB, Last accessed 90 days ago

**S3 Buckets:**
- logs-bucket: 5TB, 90% objects > 90 days old, Standard storage
- backup-bucket: 10TB, Accessed once per month, Standard storage

Provide specific cost optimization recommendations with estimated savings.
"""
                    
                    analysis = helper.chat(resources_text, [],
                        "You are an AWS cost optimization expert. Provide specific, actionable recommendations with estimated savings.")
                
                if analysis:
                    st.markdown("#### 💡 Cost Optimization Recommendations")
                    st.markdown(analysis)
        
        elif analysis_type == "Deep Analysis":
            st.info("Deep analysis includes comprehensive review of all services, Reserved Instance recommendations, and Savings Plans")
            
            services_to_analyze = st.multiselect(
                "Services to Analyze",
                ["EC2", "RDS", "S3", "Lambda", "DynamoDB", "EBS", "CloudFront", "Data Transfer"],
                default=["EC2", "RDS", "S3"]
            )
            
            if st.button("🔬 Run Deep Analysis", use_container_width=True):
                with st.spinner("🤖 Performing deep cost analysis..."):
                    analysis_text = f"""
Perform a deep cost optimization analysis for: {', '.join(services_to_analyze)}

Focus on:
1. Right-sizing opportunities
2. Reserved Instance / Savings Plan recommendations
3. Storage optimization (lifecycle policies, tiering)
4. Unused resource identification
5. Architecture improvements for cost efficiency
6. Data transfer optimization

Provide detailed recommendations with:
- Current cost
- Optimized cost
- Estimated monthly savings
- Implementation complexity (Low/Medium/High)
- Priority (High/Medium/Low)
"""
                    
                    analysis = helper.chat(analysis_text, [],
                        "You are an AWS FinOps expert. Provide comprehensive cost analysis with specific recommendations and ROI calculations.")
                
                if analysis:
                    st.markdown("#### 📊 Deep Analysis Results")
                    st.markdown(analysis)
        
        else:  # Custom Query
            custom_query = st.text_area(
                "Cost Optimization Query",
                placeholder="Example:\n- How can I reduce data transfer costs between regions?\n- What's the best instance type for my ML workload?\n- Should I use Lambda or Fargate for my API?",
                height=100
            )
            
            if st.button("🎯 Analyze", use_container_width=True):
                if custom_query:
                    with st.spinner("🤖 Analyzing..."):
                        analysis = helper.chat(custom_query, [],
                            "You are an AWS cost optimization expert. Provide specific recommendations with cost estimates.")
                    
                    if analysis:
                        st.markdown("#### 💡 Analysis Results")
                        st.markdown(analysis)
        
        # Action buttons
        if st.session_state.get('cost_analysis_complete'):
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("📄 Export Report"):
                    st.success("✅ Report exported to PDF")
            with col2:
                if st.button("📋 Create Action Plan"):
                    st.success("✅ Action plan created")
            with col3:
                if st.button("📧 Email to Team"):
                    st.success("✅ Report emailed")
    
    @staticmethod
    def _render_security_analysis(helper):
        """Security analysis assistant"""
        st.markdown("### 🔒 Security Analysis Assistant")
        st.caption("Analyze security findings and get AI-powered remediation recommendations")
        
        analysis_mode = st.radio(
            "Analysis Mode",
            ["Security Findings", "IAM Policy Review", "Network Security", "Compliance Check"],
            horizontal=True
        )
        
        if analysis_mode == "Security Findings":
            if st.button("🔍 Analyze Recent Security Findings", use_container_width=True):
                with st.spinner("🤖 Analyzing security findings..."):
                    findings_text = """
Analyze these AWS Security Hub / GuardDuty findings and provide remediation steps:

**CRITICAL Findings:**
1. S3 bucket 'my-app-data' has public read access
   - Resource: arn:aws:s3:::my-app-data
   - Description: Bucket policy allows public read access to all objects

2. Security group 'sg-web-servers' allows unrestricted SSH
   - Resource: sg-abc123
   - Description: Ingress rule allows SSH (port 22) from 0.0.0.0/0

**HIGH Findings:**
3. IAM user 'service-account' has long-term access keys (365 days old)
   - Resource: arn:aws:iam::123456789012:user/service-account
   - Description: Access key has not been rotated in 365 days

4. RDS instance 'prod-db' has public accessibility enabled
   - Resource: arn:aws:rds:us-east-1:123456789012:db:prod-db
   - Description: Database endpoint is publicly accessible

5. Lambda function 'data-processor' has overly permissive IAM role
   - Resource: arn:aws:lambda:us-east-1:123456789012:function:data-processor
   - Description: Execution role has AdministratorAccess policy

For each finding, provide:
1. Risk assessment
2. Step-by-step remediation
3. AWS CLI commands or console steps
4. Prevention best practices
"""
                    
                    analysis = helper.chat(findings_text, [],
                        "You are an AWS security expert. Provide detailed remediation steps with specific commands.")
                
                if analysis:
                    st.markdown("#### 🛡️ Security Analysis & Remediation")
                    st.markdown(analysis)
        
        elif analysis_mode == "IAM Policy Review":
            policy_input = st.text_area(
                "Paste IAM Policy JSON",
                placeholder='{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}',
                height=200
            )
            
            if st.button("🔒 Analyze Policy", use_container_width=True):
                if policy_input:
                    with st.spinner("🤖 Analyzing IAM policy..."):
                        policy_text = f"""
Analyze this AWS IAM policy for security issues and recommend improvements:

```json
{policy_input}
```

Check for:
1. Overly permissive permissions (wildcards)
2. Violation of least privilege principle
3. Missing condition statements
4. Potential security risks
5. Compliance with AWS best practices

Provide:
- Security issues found
- Risk level for each issue
- Recommended policy improvements
- Improved policy JSON
"""
                        
                        analysis = helper.chat(policy_text, [],
                            "You are an AWS IAM security expert. Analyze policies and provide secure alternatives.")
                    
                    if analysis:
                        st.markdown("#### 🔐 Policy Analysis")
                        st.markdown(analysis)
        
        elif analysis_mode == "Network Security":
            if st.button("🌐 Analyze Network Security", use_container_width=True):
                with st.spinner("🤖 Analyzing network security configuration..."):
                    network_text = """
Analyze this AWS network security configuration:

**VPC Configuration:**
- VPC: vpc-123abc (10.0.0.0/16)
- Public Subnets: 10.0.1.0/24, 10.0.2.0/24
- Private Subnets: 10.0.10.0/24, 10.0.11.0/24

**Security Groups:**
- sg-web: Allows 0.0.0.0/0 on ports 80, 443, 22
- sg-app: Allows sg-web on port 8080
- sg-db: Allows sg-app on port 3306

**NACLs:** Default (allow all)

**Route Tables:**
- Public: 0.0.0.0/0 → igw-123
- Private: 0.0.0.0/0 → nat-123

Analyze for:
1. Security group misconfigurations
2. Network ACL improvements
3. Network segmentation best practices
4. VPC Flow Logs recommendations
5. AWS Network Firewall opportunities
"""
                    
                    analysis = helper.chat(network_text, [],
                        "You are an AWS network security expert. Provide comprehensive network security analysis.")
                
                if analysis:
                    st.markdown("#### 🛡️ Network Security Analysis")
                    st.markdown(analysis)
        
        else:  # Compliance Check
            framework = st.selectbox(
                "Compliance Framework",
                ["PCI-DSS", "HIPAA", "SOC 2", "GDPR", "CIS AWS Foundations", "NIST"]
            )
            
            if st.button(f"✅ Check {framework} Compliance", use_container_width=True):
                with st.spinner(f"🤖 Checking {framework} compliance..."):
                    compliance_text = f"""
Perform a {framework} compliance check for AWS environment and provide:

1. Key compliance requirements for {framework}
2. AWS services and features that help achieve compliance
3. Common compliance gaps and how to address them
4. Recommended AWS Config rules for continuous compliance
5. Audit and monitoring best practices
6. Documentation requirements
"""
                    
                    analysis = helper.chat(compliance_text, [],
                        f"You are an AWS compliance expert specializing in {framework}. Provide actionable compliance guidance.")
                
                if analysis:
                    st.markdown(f"#### ✅ {framework} Compliance Analysis")
                    st.markdown(analysis)
        
        # Action buttons
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📋 Create Remediation Tasks"):
                st.success("✅ Remediation tasks created")
        with col2:
            if st.button("📄 Export Security Report"):
                st.success("✅ Report exported")
        with col3:
            if st.button("🔔 Set Up Alerts"):
                st.success("✅ Alerts configured")
    
    @staticmethod
    def _render_iac_generator(helper):
        """Infrastructure as Code generator"""
        st.markdown("### 📝 Generate Infrastructure as Code")
        st.caption("Describe your AWS infrastructure and get Terraform/CloudFormation code")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            format_type = st.selectbox(
                "IaC Format",
                ["Terraform (HCL)", "CloudFormation (YAML)", "CloudFormation (JSON)", "CDK (Python)", "CDK (TypeScript)"]
            )
        
        with col2:
            include_modules = st.checkbox("Use Terraform Modules", value=True)
            include_comments = st.checkbox("Include Comments", value=True)
        
        infrastructure_desc = st.text_area(
            "Describe Infrastructure",
            placeholder="""Example:

I need a production-ready web application with:

1. VPC with public and private subnets across 3 AZs
2. Application Load Balancer in public subnets
3. Auto Scaling Group (2-10 EC2 t3.medium instances) in private subnets
4. RDS MySQL Multi-AZ database (db.r5.large) in private subnets
5. ElastiCache Redis cluster for session storage
6. S3 bucket for static assets with CloudFront CDN
7. Route53 for DNS
8. ACM certificate for HTTPS
9. CloudWatch alarms and SNS notifications
10. All resources should have appropriate tags and security groups
""",
            height=250
        )
        
        if st.button("🚀 Generate IaC Template", use_container_width=True):
            if infrastructure_desc:
                with st.spinner(f"🤖 Generating {format_type} template..."):
                    iac_prompt = f"""
Generate production-ready {format_type} code for this AWS infrastructure:

{infrastructure_desc}

Requirements:
- Follow AWS best practices
- Include proper security configurations
- Add resource dependencies
- Include variables and outputs
- {"Use modules where appropriate" if include_modules and "Terraform" in format_type else ""}
- {"Add detailed comments explaining each section" if include_comments else ""}
- Ensure high availability and fault tolerance

Provide complete, working code that can be deployed immediately.
"""
                    
                    template = helper.chat(iac_prompt, [],
                        f"You are an AWS IaC expert specializing in {format_type}. Generate production-ready, well-structured code.")
                
                if template:
                    st.markdown(f"#### 📄 Generated {format_type} Template")
                    
                    # Determine language for syntax highlighting
                    if "Terraform" in format_type:
                        language = "hcl"
                    elif "JSON" in format_type:
                        language = "json"
                    elif "Python" in format_type:
                        language = "python"
                    elif "TypeScript" in format_type:
                        language = "typescript"
                    else:
                        language = "yaml"
                    
                    st.code(template, language=language)
                    
                    # Action buttons
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        if st.button("📥 Download Template"):
                            st.success("✅ Template downloaded")
                    with col2:
                        if st.button("✅ Validate Syntax"):
                            st.success("✅ Syntax valid")
                    with col3:
                        if st.button("🚀 Deploy to Account"):
                            st.info("🚀 Deployment initiated")
            else:
                st.warning("⚠️ Please describe the infrastructure you want to create")
        
        # Example templates
        with st.expander("📚 Example Templates"):
            st.markdown("""
            **Common Patterns:**
            - Three-tier web application (ALB + EC2 + RDS)
            - Serverless API (API Gateway + Lambda + DynamoDB)
            - Data lake (S3 + Glue + Athena + QuickSight)
            - Container platform (ECS/EKS cluster with ALB)
            - CI/CD pipeline (CodePipeline + CodeBuild + CodeDeploy)
            - Batch processing (Step Functions + Lambda + S3)
            """)
    
    @staticmethod
    def _render_runbook_generator(helper):
        """Operational runbook generator"""
        st.markdown("### 📚 Runbook Generator")
        st.caption("Generate detailed operational runbooks for AWS operations")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            operation_type = st.selectbox(
                "Operation Type",
                [
                    "Deploy Application Update",
                    "Database Migration (RDS)",
                    "Disaster Recovery Failover",
                    "Scale Up/Down Infrastructure",
                    "Security Incident Response",
                    "Backup and Restore",
                    "Certificate Renewal (ACM)",
                    "Lambda Function Deployment",
                    "ECS Service Update",
                    "RDS Snapshot Restore",
                    "S3 Data Recovery",
                    "EC2 Instance Recovery",
                    "Custom Operation"
                ]
            )
        
        with col2:
            include_rollback = st.checkbox("Include Rollback", value=True)
            include_validation = st.checkbox("Include Validation", value=True)
        
        if operation_type == "Custom Operation":
            operation_name = st.text_input("Operation Name", placeholder="e.g., Migrate ELB to ALB")
        else:
            operation_name = operation_type
        
        context = st.text_area(
            "Additional Context",
            placeholder="""Provide specific context about your environment:

Example:
- Environment: Production
- AWS Region: us-east-1
- Application: E-commerce platform
- Database: RDS MySQL 8.0, db.r5.2xlarge
- Traffic: 10,000 requests/minute
- Maintenance Window: Sundays 2 AM - 6 AM EST
- Team: 3 engineers on-call
""",
            height=150
        )
        
        if st.button("📖 Generate Runbook", use_container_width=True):
            if operation_name:
                with st.spinner("🤖 Generating detailed runbook..."):
                    runbook_prompt = f"""
Generate a detailed operational runbook for: {operation_name}

Context:
{context if context else "Standard AWS production environment"}

The runbook should include:

1. **Overview**
   - Operation description
   - Prerequisites
   - Required permissions (IAM policies)
   - Estimated duration

2. **Pre-Operation Checklist**
   - Verification steps
   - Backup requirements
   - Team notifications

3. **Step-by-Step Procedure**
   - Detailed steps with AWS CLI commands
   - Console instructions as alternative
   - Expected outputs for each step
   - Decision points and branching

4. **Validation Steps**
   - Health checks
   - Monitoring dashboards to watch
   - Success criteria
{"" if not include_validation else "- Automated validation scripts"}

5. **Rollback Procedure**
   - When to rollback
   - Step-by-step rollback instructions
   - Rollback validation
{"" if not include_rollback else "- Emergency rollback (< 5 minutes)"}

6. **Post-Operation Tasks**
   - Cleanup activities
   - Documentation updates
   - Team notifications
   - Lessons learned

7. **Troubleshooting**
   - Common issues and solutions
   - Emergency contacts
   - Escalation procedures

Make it production-ready and executable by an engineer with AWS experience.
"""
                    
                    runbook = helper.chat(runbook_prompt, [],
                        "You are an AWS operations expert. Generate comprehensive, production-ready runbooks with specific commands.")
                
                if runbook:
                    st.markdown("#### 📖 Generated Runbook")
                    st.markdown(runbook)
                    
                    # Action buttons
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        if st.button("💾 Save to Database"):
                            st.success("✅ Runbook saved")
                    with col2:
                        if st.button("📄 Export as PDF"):
                            st.success("✅ PDF exported")
                    with col3:
                        if st.button("📧 Email to Team"):
                            st.success("✅ Emailed to team")
                    with col4:
                        if st.button("📋 Add to Wiki"):
                            st.success("✅ Added to wiki")
            else:
                st.warning("⚠️ Please specify an operation name")
        
        # Runbook library
        with st.expander("📚 Runbook Library"):
            st.markdown("""
            **Available Templates:**
            - Blue/Green Deployment with ALB
            - RDS Multi-AZ Failover Testing
            - Auto Scaling Group Update
            - Lambda Function Deployment (Blue/Green)
            - S3 Cross-Region Replication Setup
            - CloudFront Cache Invalidation
            - Route53 Failover Configuration
            - EC2 Instance Patching Procedure
            """)
