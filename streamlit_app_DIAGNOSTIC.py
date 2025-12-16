"""
DIAGNOSTIC VERSION - Shows exactly what's happening
Deploy this to see what's wrong
"""

import streamlit as st
from datetime import datetime
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from config_settings import AppConfig
from core_session_manager import SessionManager
from components_navigation import Navigation
from components_sidebar import GlobalSidebar

# Page configuration
st.set_page_config(
    page_title="Cloud Infrastructure Development Platform - DIAGNOSTIC",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# DIAGNOSTIC CSS - FORCES WHITE CARDS
st.markdown("""
<style>
/* DIAGNOSTIC MODE - NUCLEAR CSS */
body, html, .stApp, .main {
    background-color: #1a1a1a !important;
}

/* FORCE everything to be visible */
p, span, div, label, h1, h2, h3 {
    color: white !important;
}
</style>
""", unsafe_allow_html=True)

# DIAGNOSTIC HEADER
st.markdown("""
<div style="background: red; padding: 20px; text-align: center; color: white !important;">
    <h1 style="color: white !important;">🔍 DIAGNOSTIC MODE ACTIVE</h1>
    <p style="color: white !important;">This page shows what's actually deployed</p>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# DIAGNOSTIC INFORMATION
st.error("🔍 DIAGNOSTIC INFORMATION")

col1, col2 = st.columns(2)

with col1:
    st.markdown("### 📦 Python Environment")
    st.write(f"**Python version:** {sys.version.split()[0]}")
    st.write(f"**Current directory:** {Path.cwd()}")
    st.write(f"**File location:** {__file__}")
    
    st.markdown("### 📁 File Checks")
    
    # Check if aws_theme.py exists and can be imported
    try:
        import aws_theme
        st.success("✅ aws_theme.py found and importable")
        st.write(f"**Location:** {aws_theme.__file__}")
        
        # Check file size
        file_size = Path(aws_theme.__file__).stat().st_size
        st.write(f"**File size:** {file_size:,} bytes ({file_size/1024:.1f} KB)")
        
        # Check if it has the aws_metric_card function
        if hasattr(aws_theme.AWSTheme, 'aws_metric_card'):
            st.success("✅ AWSTheme.aws_metric_card exists")
        else:
            st.error("❌ AWSTheme.aws_metric_card NOT FOUND")
            
    except ImportError as e:
        st.error(f"❌ Cannot import aws_theme: {e}")
    
    # Check modules_dashboard.py
    try:
        import modules_dashboard
        st.success("✅ modules_dashboard.py found")
        st.write(f"**Location:** {modules_dashboard.__file__}")
    except ImportError as e:
        st.error(f"❌ Cannot import modules_dashboard: {e}")

with col2:
    st.markdown("### 🎨 Theme Information")
    
    st.write("**Deployment timestamp:** " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    st.markdown("### 🔧 Expected Behavior")
    st.write("After fix, you should see:")
    st.write("- ✅ This diagnostic header in RED")
    st.write("- ✅ White text everywhere")
    st.write("- ✅ Metric cards below with visible text")
    st.write("- ✅ File size ~15 KB for aws_theme.py")

st.markdown("---")

# TEST METRIC CARDS - THREE VERSIONS
st.markdown("## 🧪 TEST METRICS - Which one is visible?")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("### Test 1: Direct HTML (Light)")
    st.markdown("""
    <div style="
        background: white;
        border: 3px solid red;
        padding: 20px;
        border-radius: 10px;
    ">
        <div style="color: red !important; font-size: 14px; font-weight: bold;">
            TEST LABEL
        </div>
        <div style="color: black !important; font-size: 42px; font-weight: bold;">
            123
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.caption("If you can see '123', light cards work!")

with col2:
    st.markdown("### Test 2: Direct HTML (Dark)")
    st.markdown("""
    <div style="
        background: #161E2D;
        border: 3px solid orange;
        padding: 20px;
        border-radius: 10px;
    ">
        <div style="color: orange !important; font-size: 14px; font-weight: bold;">
            TEST LABEL
        </div>
        <div style="color: white !important; font-size: 42px; font-weight: bold;">
            456
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.caption("If you can see '456', dark cards work!")

with col3:
    st.markdown("### Test 3: Using AWSTheme")
    try:
        from aws_theme import AWSTheme
        AWSTheme.aws_metric_card(
            label="TEST LABEL",
            value="789",
            icon="🧪"
        )
        st.caption("If you can see '789', aws_theme works!")
    except Exception as e:
        st.error(f"Error: {e}")

st.markdown("---")

# ACTUAL DASHBOARD
st.markdown("## 📊 Actual Dashboard (for comparison)")

def main():
    """Main application entry point"""
    
    # Initialize session
    SessionManager.initialize()
    
    # Render global sidebar
    GlobalSidebar.render()
    
    # Render main navigation
    Navigation.render()

if __name__ == "__main__":
    main()

st.markdown("---")

# INSTRUCTIONS
st.markdown("## 📋 DIAGNOSTIC INSTRUCTIONS")

st.info("""
**After deploying this diagnostic version:**

1. **Take a screenshot** of this ENTIRE page
2. **Check which test metrics you can see:**
   - Test 1 (white card with red border) - can you see "123"?
   - Test 2 (dark card with orange border) - can you see "456"?
   - Test 3 (aws_theme card) - can you see "789"?
3. **Read the File Checks section** - does it show ✅ or ❌?
4. **Send me the screenshot** - I'll diagnose the exact problem!

**This will tell us:**
- ✅ If files are actually deploying
- ✅ Which card style works in your environment
- ✅ If there's an import/path issue
- ✅ What the actual problem is
""")

st.error("🔴 DIAGNOSTIC MODE - Replace this file with real streamlit_app.py after testing!")
