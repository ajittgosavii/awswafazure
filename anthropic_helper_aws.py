"""
AWS-Specific Anthropic Helper
AI assistance tailored for AWS services, architecture, and best practices
"""

from typing import Any, Dict, List, Optional
import streamlit as st
import json

class AWSAnthropicHelper:
    """AWS-specific AI helper with Claude integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize AWS AI helper"""
        self.api_key = api_key or self._get_api_key()
        self.client = None
        
        if self.api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                st.warning("⚠️ Anthropic library not installed. Run: pip install anthropic")
            except Exception as e:
                st.warning(f"⚠️ Could not initialize Anthropic client: {str(e)}")
    
    @staticmethod
    def _get_api_key() -> Optional[str]:
        """Get API key from secrets or environment"""
        if hasattr(st, 'secrets'):
            try:
                if 'anthropic' in st.secrets and 'api_key' in st.secrets['anthropic']:
                    return st.secrets['anthropic']['api_key']
                elif 'ANTHROPIC_API_KEY' in st.secrets:
                    return st.secrets['ANTHROPIC_API_KEY']
            except Exception:
                pass
        
        import os
        return os.getenv('ANTHROPIC_API_KEY')
    
    def chat(self, prompt: str, context: Optional[Any] = None, system_prompt: Optional[str] = None) -> str:
        """AWS-focused chat with Claude"""
        if not self.client:
            return "⚠️ AI features not available. Please configure ANTHROPIC_API_KEY."
        
        # Default AWS-specific system prompt
        if not system_prompt:
            system_prompt = """You are an AWS Solutions Architect Expert with deep knowledge of:
- AWS Well-Architected Framework (all 6 pillars)
- AWS service catalog and best practices
- Infrastructure as Code (CloudFormation, Terraform, CDK)
- AWS security and compliance standards
- Cost optimization strategies
- High availability and disaster recovery
- AWS CLI and SDK usage

Provide practical, production-ready guidance specific to AWS services and patterns."""

        try:
            # Build context
            if context:
                if isinstance(context, str):
                    full_prompt = f"Context: {context}\n\nQuestion: {prompt}"
                elif isinstance(context, list):
                    context_str = "\n".join([f"{msg.get('role', 'unknown')}: {msg.get('content', '')}" for msg in context])
                    full_prompt = f"Previous conversation:\n{context_str}\n\nUser: {prompt}"
                elif isinstance(context, dict):
                    context_str = json.dumps(context, indent=2)
                    full_prompt = f"Context:\n{context_str}\n\nQuestion: {prompt}"
                else:
                    full_prompt = prompt
            else:
                full_prompt = prompt
            
            # Call Claude API with AWS-specific system prompt
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                system=system_prompt,
                messages=[{"role": "user", "content": full_prompt}]
            )
            
            response_text = ""
            for content_block in message.content:
                if hasattr(content_block, 'text'):
                    response_text += content_block.text
            
            return response_text
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def generate_architecture_recommendation(self, requirements: Dict) -> str:
        """Generate AWS-specific architecture recommendation"""
        if not self.client:
            return "⚠️ AI features not available."
        
        prompt = f"""As an AWS Solutions Architect, design a production-ready architecture using AWS services:

**Requirements:**
- Services needed: {', '.join(requirements.get('services', []))}
- Traffic: {requirements.get('traffic', 'Unknown')}
- Compliance: {', '.join(requirements.get('compliance', []))}
- Budget: {requirements.get('budget', 'Unknown')}
- High Availability: {'Yes' if requirements.get('ha_required') else 'No'}
- Additional: {requirements.get('additional', 'None')}

**Provide:**
1. AWS service selection with justification
2. Architecture diagram description (using AWS services)
3. Multi-AZ/Multi-region design
4. Security architecture (IAM, security groups, encryption)
5. Cost breakdown and optimization
6. Scalability strategy (Auto Scaling, ELB, etc.)
7. Monitoring and logging (CloudWatch, CloudTrail)
8. Disaster recovery plan
9. Implementation roadmap with CloudFormation/CDK
10. Well-Architected Framework alignment
"""
        
        return self.chat(prompt)
    
    def analyze_cost_optimization(self, resources: List[Dict]) -> str:
        """Analyze AWS resources for cost optimization"""
        if not self.client:
            return "⚠️ AI features not available."
        
        resources_str = json.dumps(resources, indent=2)
        prompt = f"""As an AWS cost optimization expert, analyze these resources:

{resources_str}

**For each resource provide:**
1. Current AWS pricing estimate
2. Utilization metrics and patterns
3. Right-sizing recommendations (EC2 instance types, RDS classes)
4. AWS pricing model optimization (RI, Savings Plans, Spot)
5. Alternative AWS services (e.g., ECS → Lambda, EBS → EFS)
6. Storage class optimization (S3 Intelligent-Tiering)
7. Monthly savings potential
8. Implementation steps (AWS CLI/Console)
9. Risk assessment
10. AWS Cost Explorer and Trusted Advisor insights
"""
        
        return self.chat(prompt)
    
    def analyze_security_findings(self, findings: List[Dict]) -> str:
        """Analyze AWS security findings"""
        if not self.client:
            return "⚠️ AI features not available."
        
        findings_str = json.dumps(findings, indent=2)
        prompt = f"""As an AWS security expert, analyze these findings:

{findings_str}

**For each finding provide:**
1. AWS security impact assessment
2. Related AWS services and configurations
3. Step-by-step remediation (AWS CLI/Console)
4. IAM policy recommendations
5. Security group and NACL fixes
6. AWS Config rules to prevent recurrence
7. Compliance mapping (PCI-DSS, HIPAA, SOC 2)
8. AWS Security Hub integration
9. CloudTrail logging recommendations
10. Cost impact of remediation
"""
        
        return self.chat(prompt)
    
    def generate_iac_template(self, infrastructure: Dict, format_type: str) -> str:
        """Generate AWS IaC template (CloudFormation, Terraform, CDK)"""
        if not self.client:
            return "⚠️ AI features not available."
        
        desc = infrastructure.get('description', '')
        
        # Map format types to AWS-specific
        format_mapping = {
            'cloudformation': 'AWS CloudFormation YAML',
            'terraform': 'Terraform for AWS',
            'cdk': 'AWS CDK (Python)',
            'sam': 'AWS SAM template'
        }
        
        format_name = format_mapping.get(format_type.lower(), format_type)
        
        prompt = f"""Generate production-ready {format_name} code:

{desc}

**Requirements:**
1. Use AWS best practices and naming conventions
2. Include all necessary AWS resources
3. Implement AWS security best practices
4. Add comprehensive tagging strategy
5. Include Parameters/Variables for flexibility
6. Add Outputs for cross-stack references
7. Use AWS-managed policies where appropriate
8. Include CloudWatch alarms and monitoring
9. Add comments explaining AWS-specific configurations
10. Make it ready for AWS deployment

Generate ONLY the code, no explanations."""
        
        return self.chat(prompt)
    
    def generate_runbook(self, operation: str, context: Dict) -> str:
        """Generate AWS-specific operational runbook"""
        if not self.client:
            return "⚠️ AI features not available."
        
        context_str = context.get('context', 'Standard AWS environment')
        prompt = f"""Generate a detailed AWS operational runbook for: {operation}

Context: {context_str}

**Include:**
1. **Overview** - Purpose and AWS services involved
2. **Prerequisites** - AWS IAM permissions, CLI/SDK setup
3. **Pre-flight Checks** - AWS service health, quotas
4. **Step-by-Step Procedures** - AWS Console and CLI commands
5. **Validation** - AWS CloudWatch metrics, logs
6. **Rollback** - AWS-specific rollback procedures
7. **Troubleshooting** - Common AWS issues and solutions
8. **Communication** - SNS/EventBridge notifications
9. **Post-operation** - CloudTrail audit, cost impact
10. **Automation** - Lambda/Step Functions opportunities

Use AWS CLI commands, CloudFormation snippets, and AWS Console screenshots descriptions.
"""
        
        return self.chat(prompt)
    
    def is_available(self) -> bool:
        """Check if AI features are available"""
        return self.client is not None


@st.cache_resource
def get_aws_anthropic_helper() -> AWSAnthropicHelper:
    """Get cached AWS AI helper instance"""
    return AWSAnthropicHelper()
