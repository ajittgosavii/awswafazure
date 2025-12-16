"""
Anthropic Helper - AI Integration Module
Provides AnthropicHelper class and convenience functions
"""

from typing import Any, Dict, List, Optional
import streamlit as st
import json

class AnthropicHelper:
    """Helper class for Anthropic Claude AI integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize Anthropic helper"""
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
        # Try Streamlit secrets first
        if hasattr(st, 'secrets'):
            try:
                if 'anthropic' in st.secrets and 'api_key' in st.secrets['anthropic']:
                    return st.secrets['anthropic']['api_key']
                elif 'ANTHROPIC_API_KEY' in st.secrets:
                    return st.secrets['ANTHROPIC_API_KEY']
            except Exception:
                pass
        
        # Try environment variable
        import os
        return os.getenv('ANTHROPIC_API_KEY')
    
    def chat(self, prompt: str, context: Optional[Any] = None) -> str:
        """
        Send a chat message to Claude and get response
        
        Args:
            prompt: The user's message/question
            context: Optional context (can be string, list, dict)
            
        Returns:
            Claude's response as a string
        """
        if not self.client:
            return "⚠️ AI features not available. Please configure ANTHROPIC_API_KEY."
        
        try:
            # Build the message with context
            if context:
                if isinstance(context, str):
                    full_prompt = f"Context: {context}\n\nQuestion: {prompt}"
                elif isinstance(context, list):
                    # Handle chat history format
                    context_str = "\n".join([f"{msg.get('role', 'unknown')}: {msg.get('content', '')}" for msg in context])
                    full_prompt = f"Previous conversation:\n{context_str}\n\nUser: {prompt}"
                elif isinstance(context, dict):
                    context_str = json.dumps(context, indent=2)
                    full_prompt = f"Context:\n{context_str}\n\nQuestion: {prompt}"
                else:
                    full_prompt = prompt
            else:
                full_prompt = prompt
            
            # Call Claude API
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": full_prompt}
                ]
            )
            
            # Extract response text
            response_text = ""
            for content_block in message.content:
                if hasattr(content_block, 'text'):
                    response_text += content_block.text
            
            return response_text
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def generate_architecture_recommendation(self, requirements: Dict) -> str:
        """Generate architecture recommendation based on requirements"""
        if not self.client:
            return "⚠️ AI features not available."
        
        prompt = f"""As an AWS Solutions Architect, provide a detailed architecture recommendation based on these requirements:

Services: {', '.join(requirements.get('services', []))}
Expected Traffic: {requirements.get('traffic', 'Unknown')}
Compliance: {', '.join(requirements.get('compliance', []))}
Budget: {requirements.get('budget', 'Unknown')}
High Availability: {'Yes' if requirements.get('ha_required') else 'No'}
Additional Requirements: {requirements.get('additional', 'None')}

Please provide:
1. Overall architecture design
2. Specific AWS services to use
3. Security best practices
4. Cost optimization strategies
5. Scalability considerations
6. Implementation roadmap
"""
        
        return self.chat(prompt)
    
    def analyze_cost_optimization(self, resources: List[Dict]) -> str:
        """Analyze resources for cost optimization opportunities"""
        if not self.client:
            return "⚠️ AI features not available."
        
        resources_str = json.dumps(resources, indent=2)
        prompt = f"""As an AWS cost optimization expert, analyze these resources and provide specific recommendations:

{resources_str}

For each resource, provide:
1. Current cost estimate
2. Utilization assessment
3. Right-sizing recommendations
4. Alternative service options
5. Potential monthly savings
6. Implementation steps
7. Risk assessment of each change
"""
        
        return self.chat(prompt)
    
    def analyze_security_findings(self, findings: List[Dict]) -> str:
        """Analyze security findings and provide remediation recommendations"""
        if not self.client:
            return "⚠️ AI features not available."
        
        findings_str = json.dumps(findings, indent=2)
        prompt = f"""As an AWS security expert, analyze these security findings and provide detailed remediation guidance:

{findings_str}

For each finding, provide:
1. Risk assessment
2. Potential impact
3. Step-by-step remediation instructions
4. AWS CLI/Console commands to fix
5. Prevention strategies
6. Compliance impact
"""
        
        return self.chat(prompt)
    
    def generate_iac_template(self, infrastructure: Dict, format_type: str) -> str:
        """Generate Infrastructure as Code template"""
        if not self.client:
            return "⚠️ AI features not available."
        
        desc = infrastructure.get('description', '')
        prompt = f"""Generate a complete {format_type} template for this infrastructure:

{desc}

Requirements:
1. Include all necessary resources
2. Follow best practices
3. Add meaningful comments
4. Include variables/parameters
5. Add outputs
6. Ensure security best practices
7. Make it production-ready

Generate ONLY the code, no explanations before or after.
"""
        
        return self.chat(prompt)
    
    def generate_runbook(self, operation: str, context: Dict) -> str:
        """Generate operational runbook"""
        if not self.client:
            return "⚠️ AI features not available."
        
        context_str = context.get('context', 'Standard AWS environment')
        prompt = f"""Generate a detailed operational runbook for: {operation}

Context: {context_str}

The runbook should include:
1. **Overview** - Purpose and scope
2. **Prerequisites** - Required access, tools, knowledge
3. **Pre-flight Checks** - What to verify before starting
4. **Step-by-Step Procedures** - Detailed instructions
5. **Validation Steps** - How to verify success
6. **Rollback Procedures** - How to undo if needed
7. **Troubleshooting** - Common issues and solutions
8. **Communication Plan** - Who to notify and when
9. **Post-operation Tasks** - Cleanup and documentation

Be specific with AWS CLI commands, console steps, and verification methods.
"""
        
        return self.chat(prompt)
    
    def is_available(self) -> bool:
        """Check if AI features are available"""
        return self.client is not None


# ==================================================================================
# HELPER FACTORY FUNCTION
# ==================================================================================

@st.cache_resource
def get_anthropic_helper() -> AnthropicHelper:
    """Get cached Anthropic helper instance"""
    return AnthropicHelper()