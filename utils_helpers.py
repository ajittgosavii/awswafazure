"""
Helper Utilities
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import streamlit as st

class Helpers:
    """General helper functions"""
    
    @staticmethod
    def format_currency(amount: float, currency: str = "USD") -> str:
        """Format currency amount"""
        if currency == "USD":
            if amount >= 1_000_000:
                return f"${amount/1_000_000:.2f}M"
            elif amount >= 1_000:
                return f"${amount/1_000:.1f}K"
            else:
                return f"${amount:.2f}"
        return f"{amount:.2f}"
    
    @staticmethod
    def format_number(num: int) -> str:
        """Format large numbers with K/M/B suffix"""
        if num >= 1_000_000_000:
            return f"{num/1_000_000_000:.1f}B"
        elif num >= 1_000_000:
            return f"{num/1_000_000:.1f}M"
        elif num >= 1_000:
            return f"{num/1_000:.1f}K"
        else:
            return str(num)
    
    @staticmethod
    def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Format datetime"""
        if isinstance(dt, str):
            return dt
        return dt.strftime(format_str)
    
    @staticmethod
    def time_ago(dt: datetime) -> str:
        """Get human-readable time ago"""
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        diff = now - dt
        
        if diff.days > 365:
            return f"{diff.days // 365} year{'s' if diff.days // 365 > 1 else ''} ago"
        elif diff.days > 30:
            return f"{diff.days // 30} month{'s' if diff.days // 30 > 1 else ''} ago"
        elif diff.days > 0:
            return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600} hour{'s' if diff.seconds // 3600 > 1 else ''} ago"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60} minute{'s' if diff.seconds // 60 > 1 else ''} ago"
        else:
            return "just now"
    
    @staticmethod
    def get_status_icon(status: str) -> str:
        """Get status icon"""
        status_icons = {
            'running': '🟢',
            'stopped': '🔴',
            'pending': '🟡',
            'active': '✅',
            'inactive': '❌',
            'healthy': '💚',
            'unhealthy': '💔',
            'warning': '⚠️',
            'error': '🚨',
            'success': '✅',
            'failed': '❌',
            'in_progress': '⏳'
        }
        return status_icons.get(status.lower(), '⚪')
    
    @staticmethod
    def get_environment_badge(environment: str) -> str:
        """Get HTML badge for environment"""
        colors = {
            'production': '#dc3545',
            'staging': '#ffc107',
            'development': '#28a745',
            'sandbox': '#17a2b8'
        }
        color = colors.get(environment.lower(), '#6c757d')
        return f'<span style="background:{color};color:white;padding:0.25rem 0.75rem;border-radius:0.25rem;font-size:0.875rem;font-weight:600;">{environment.upper()}</span>'
    
    @staticmethod
    def truncate_string(text: str, length: int = 50) -> str:
        """Truncate string with ellipsis"""
        if len(text) <= length:
            return text
        return text[:length-3] + "..."
    
    @staticmethod
    def get_percentage_change(current: float, previous: float) -> tuple[float, str]:
        """Calculate percentage change and direction"""
        if previous == 0:
            return 0, "neutral"
        
        change = ((current - previous) / previous) * 100
        direction = "up" if change > 0 else "down" if change < 0 else "neutral"
        return abs(change), direction
    
    @staticmethod
    def show_metric_card(title: str, value: str, delta: Optional[str] = None, help_text: Optional[str] = None):
        """Display a metric card"""
        col = st.columns(1)[0]
        with col:
            st.metric(
                label=title,
                value=value,
                delta=delta,
                help=help_text
            )
    
    @staticmethod
    def show_success(message: str):
        """Show success message"""
        st.success(f"✅ {message}")
    
    @staticmethod
    def show_error(message: str):
        """Show error message"""
        st.error(f"❌ {message}")
    
    @staticmethod
    def show_warning(message: str):
        """Show warning message"""
        st.warning(f"⚠️ {message}")
    
    @staticmethod
    def show_info(message: str):
        """Show info message"""
        st.info(f"ℹ️ {message}")
    
    @staticmethod
    def create_download_link(data: Any, filename: str, label: str = "Download"):
        """Create download button"""
        import json
        import base64
        
        if isinstance(data, dict) or isinstance(data, list):
            json_str = json.dumps(data, indent=2)
            b64 = base64.b64encode(json_str.encode()).decode()
            href = f'<a href="data:application/json;base64,{b64}" download="{filename}">{label}</a>'
            st.markdown(href, unsafe_allow_html=True)


# ==================================================================================
# ANTHROPIC HELPER CLASS - AI FEATURES
# ==================================================================================

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
    
    def chat(self, prompt: str, context: Optional[str] = None) -> str:
        """
        Send a chat message to Claude and get response
        
        Args:
            prompt: The user's message/question
            context: Optional context to provide to Claude
            
        Returns:
            Claude's response as a string
        """
        if not self.client:
            return "⚠️ AI features not available. Please configure ANTHROPIC_API_KEY."
        
        try:
            # Build the message
            if context:
                full_prompt = f"Context: {context}\n\nQuestion: {prompt}"
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
    
    def is_available(self) -> bool:
        """Check if AI features are available"""
        return self.client is not None


# ==================================================================================
# HELPER FACTORY FUNCTIONS
# ==================================================================================

@st.cache_resource
def get_anthropic_helper() -> AnthropicHelper:
    """Get cached Anthropic helper instance"""
    return AnthropicHelper()