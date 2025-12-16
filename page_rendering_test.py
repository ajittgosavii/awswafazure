"""
Azure Card Rendering Test
This tests the exact rendering of the Azure card component
"""

import streamlit as st
from azure_theme import AzureTheme
from config_settings import AppConfig

st.title("🧪 Azure Card Rendering Test")

st.markdown("""
This page tests if the Azure card component is rendering HTML correctly.
""")

st.markdown("---")

st.subheader("Test 1: Direct HTML vs Markdown Comparison")

col1, col2 = st.columns(2)

with col1:
    st.markdown("### ❌ OLD WAY (Broken)")
    st.markdown("Using markdown ** syntax:")
    
    AzureTheme.azure_card(
        title="Test Card - Markdown Syntax",
        content="""
        **Subscription ID:** 12345678<br>
        **Environment:** Production<br>
        **Regions:** East US, West US<br>
        """,
        icon="🔷"
    )

with col2:
    st.markdown("### ✅ NEW WAY (Fixed)")
    st.markdown("Using HTML <strong> tags:")
    
    AzureTheme.azure_card(
        title="Test Card - HTML Tags",
        content="""
        <strong>Subscription ID:</strong> 12345678<br>
        <strong>Environment:</strong> Production<br>
        <strong>Regions:</strong> East US, West US<br>
        """,
        icon="🔷"
    )

st.markdown("---")

st.subheader("Test 2: Actual Dashboard Code")

st.markdown("**This is what the dashboard actually renders:**")

# Load real subscriptions
subscriptions = AppConfig.load_azure_subscriptions()

if subscriptions:
    sub = subscriptions[0]
    
    st.markdown(f"**Data source:** {sub.subscription_name}")
    
    # Show the EXACT content string that's generated
    content_string = f"""
    <strong>Subscription ID:</strong> {sub.subscription_id[:8]}...{sub.subscription_id[-4:]}<br>
    <strong>Environment:</strong> {sub.environment.title()}<br>
    <strong>Regions:</strong> {', '.join(sub.regions[:3])} {f'(+{len(sub.regions)-3} more)' if len(sub.regions) > 3 else ''}<br>
    <strong>Cost Center:</strong> {sub.cost_center or 'Not set'}<br>
    <strong>Owner:</strong> {sub.owner_email or 'Not set'}
    """
    
    st.markdown("**Content string being passed to azure_card:**")
    st.code(content_string, language='html')
    
    st.markdown("**Rendered result:**")
    AzureTheme.azure_card(
        title=sub.subscription_name,
        content=content_string,
        icon="🔷"
    )

st.markdown("---")

st.subheader("📊 What You Should See")

st.markdown("""
**In the FIXED version (right column / Test 2):**
- ✅ Bold labels (not `**text**`)
- ✅ Proper line breaks (not `<br>` visible)
- ✅ Clean formatting
- ✅ No closing `</div>` tags

**If you see the OLD way (left column) in your dashboard:**
- ❌ The file didn't actually update
- ❌ Need to upload the file again
- ❌ OR there's a caching issue

**If Test 2 looks GOOD but your actual dashboard looks BAD:**
- 🔄 Use the Cache Clear page
- 🔄 Hard refresh browser (Ctrl+F5)
- 🔄 Close all tabs and reopen
""")

st.markdown("---")

st.subheader("🔍 Module File Check")

# Check what the actual file contains
try:
    import os
    if os.path.exists('azure_modules_dashboard.py'):
        with open('azure_modules_dashboard.py', 'r') as f:
            content = f.read()
            
        if '<strong>Subscription ID:</strong>' in content:
            st.success("✅ azure_modules_dashboard.py file contains FIXED code (<strong> tags)")
        elif '**Subscription ID:**' in content:
            st.error("❌ azure_modules_dashboard.py file still has OLD code (** markdown)")
            st.warning("👉 Re-upload the file from CloudIDP_v3_TriCloud_FINAL.zip")
        else:
            st.warning("⚠️ Cannot determine file version")
            
        # Show relevant snippet
        lines = content.split('\n')
        if len(lines) > 85:
            st.markdown("**File content around line 85:**")
            st.code('\n'.join(lines[82:92]), language='python')
    else:
        st.error("❌ File not found in app directory")
        
except Exception as e:
    st.error(f"Error checking file: {e}")
