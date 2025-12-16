"""
Version Diagnostic Tool
Add this as a temporary page to verify which code version is running
"""

import streamlit as st

st.title("🔍 Version Diagnostic Tool")

st.markdown("""
This tool checks which version of the code is actually running in your Streamlit Cloud app.
""")

st.markdown("---")

# Check azure_modules_dashboard.py
st.subheader("1️⃣ Checking azure_modules_dashboard.py")

try:
    with open('azure_modules_dashboard.py', 'r') as f:
        content = f.read()
        
    # Look for the key line that should be changed
    if '<strong>Subscription ID:</strong>' in content:
        st.success("✅ FIXED VERSION - File contains <strong> tags (correct HTML)")
        st.code('<strong>Subscription ID:</strong> {sub.subscription_id}', language='html')
    elif '**Subscription ID:**' in content:
        st.error("❌ OLD VERSION - File still contains ** markdown syntax")
        st.code('**Subscription ID:** {sub.subscription_id}', language='html')
    else:
        st.warning("⚠️ UNKNOWN - Cannot find subscription ID line")
        
    # Show a snippet
    st.markdown("**File snippet around line 85:**")
    lines = content.split('\n')
    if len(lines) > 85:
        snippet = '\n'.join(lines[82:92])
        st.code(snippet, language='python')
        
except Exception as e:
    st.error(f"Error reading file: {e}")

st.markdown("---")

# Check gcp_modules_dashboard.py
st.subheader("2️⃣ Checking gcp_modules_dashboard.py")

try:
    with open('gcp_modules_dashboard.py', 'r') as f:
        content = f.read()
        
    # Look for the key line that should be changed
    if '<strong>Project ID:</strong>' in content:
        st.success("✅ FIXED VERSION - File contains <strong> tags")
    elif '**Project ID:**' in content:
        st.error("❌ OLD VERSION - File still contains ** markdown syntax")
    else:
        st.warning("⚠️ UNKNOWN - Cannot find project ID line")
        
except Exception as e:
    st.error(f"Error reading file: {e}")

st.markdown("---")

# Check components_sidebar.py
st.subheader("3️⃣ Checking components_sidebar.py")

try:
    with open('components_sidebar.py', 'r') as f:
        content = f.read()
        
    # Look for the key line that should be changed
    if 'len(active_items)' in content:
        st.success("✅ FIXED VERSION - Uses active_items variable")
    elif 'len(active_accounts)' in content:
        st.error("❌ OLD VERSION - Still uses active_accounts variable")
    else:
        st.warning("⚠️ UNKNOWN - Cannot find metric line")
        
except Exception as e:
    st.error(f"Error reading file: {e}")

st.markdown("---")

st.subheader("📊 Summary")

st.markdown("""
If ALL THREE files show ✅ FIXED VERSION but you still see the bug:
1. Clear Streamlit cache: Click hamburger menu → Clear cache
2. Hard refresh browser: Ctrl+F5 (Windows) or Cmd+Shift+R (Mac)
3. Close and reopen browser completely
4. Try in incognito/private window

If any file shows ❌ OLD VERSION:
- The file upload didn't work correctly
- Try uploading again OR use git command line
""")

st.markdown("---")

st.subheader("🔄 Force Module Reload")

if st.button("🔥 Force Reload All Modules"):
    import sys
    modules_to_reload = [
        'azure_modules_dashboard',
        'gcp_modules_dashboard', 
        'components_sidebar',
        'azure_theme',
        'gcp_theme'
    ]
    
    for module in modules_to_reload:
        if module in sys.modules:
            del sys.modules[module]
    
    st.cache_data.clear()
    st.success("✅ Modules unloaded and cache cleared! Click 'Rerun' or refresh page.")
    st.button("🔄 Rerun App", on_click=st.rerun)
