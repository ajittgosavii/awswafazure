"""
Metric Fix Module - White Text Metrics for Dark Backgrounds
Bypasses CSS issues by using inline HTML styles
"""

import streamlit as st
from typing import Optional

def metric_with_white_text(
    label: str,
    value: str,
    delta: Optional[str] = None,
    delta_color: str = "normal",
    help: Optional[str] = None,
    icon: Optional[str] = None
):
    """
    Custom metric with WHITE text that's always visible on dark backgrounds.
    
    This function bypasses all CSS issues by using inline HTML styles.
    Perfect for Streamlit Cloud where CSS changes require Git pushes.
    
    Args:
        label: The metric label (e.g., "Connected Accounts")
        value: The metric value (e.g., "1" or "$0.00")
        delta: Optional delta value (e.g., "+5%" or "↑ 12%")
        delta_color: "normal", "inverse", or "off"
        help: Optional help text (shows on hover)
        icon: Optional emoji icon (e.g., "🔗", "📦")
    
    Example:
        metric_with_white_text("Connected Accounts", "5", icon="🔗")
        metric_with_white_text("Total Cost", "$1,234", delta="↑ 5%")
    """
    
    # Icon HTML
    icon_html = ""
    if icon:
        icon_html = f'<span style="font-size: 24px; margin-right: 8px;">{icon}</span>'
    
    # Delta HTML
    delta_html = ""
    if delta:
        delta_color_style = "#B0B0B0"  # Light gray for delta
        if delta_color == "inverse":
            delta_color_style = "#FF6B6B" if delta.startswith("-") else "#4ECDC4"
        elif delta_color == "normal":
            delta_color_style = "#4ECDC4" if delta.startswith("+") or delta.startswith("↑") else "#FF6B6B"
        
        delta_html = f"""
        <div style="color: {delta_color_style} !important; 
                    font-size: 14px !important; 
                    margin-top: 4px !important;
                    font-weight: 400 !important;">
            {delta}
        </div>
        """
    
    # Help tooltip
    help_attr = f'title="{help}"' if help else ''
    
    # Complete metric HTML with FORCED white text
    metric_html = f"""
    <div style="
        background-color: transparent !important;
        padding: 12px !important;
        margin: 0 !important;
        min-height: 100px !important;
    " {help_attr}>
        <div style="
            color: rgba(255, 255, 255, 0.7) !important;
            font-size: 14px !important;
            font-weight: 500 !important;
            margin-bottom: 8px !important;
            text-transform: uppercase !important;
            letter-spacing: 0.5px !important;
        ">
            {icon_html}{label}
        </div>
        <div style="
            color: white !important;
            font-size: 36px !important;
            font-weight: 600 !important;
            line-height: 1.2 !important;
            margin: 0 !important;
        ">
            {value}
        </div>
        {delta_html}
    </div>
    """
    
    st.markdown(metric_html, unsafe_allow_html=True)


def aws_metric_card(label: str, value: str, icon: str = "", delta: Optional[str] = None):
    """
    AWS-themed metric card with white text (replaces AWSTheme.aws_metric_card).
    
    This is a drop-in replacement for AWSTheme.aws_metric_card() that ensures
    text is always visible on dark backgrounds.
    
    Args:
        label: Metric label
        value: Metric value
        icon: Emoji icon (optional)
        delta: Delta value (optional)
    
    Example:
        aws_metric_card("Connected Accounts", "5", icon="🔗")
    """
    metric_with_white_text(
        label=label,
        value=value,
        icon=icon if icon else None,
        delta=delta
    )
