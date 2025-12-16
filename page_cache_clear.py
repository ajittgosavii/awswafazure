"""
🚨 EMERGENCY CACHE CLEAR
Add this file and navigate to it in your app to force clear all caches
"""

import streamlit as st
import sys

st.title("🚨 Emergency Cache Clear")

st.markdown("""
**Use this page if you updated files but still see old formatting.**

This will:
1. Clear all Streamlit caches
2. Unload all dashboard modules from memory
3. Force reload on next page visit
""")

st.markdown("---")

if st.button("🔥 CLEAR EVERYTHING", type="primary", use_container_width=True):
    
    # Clear Streamlit caches
    st.cache_data.clear()
    st.cache_resource.clear()
    
    # Remove modules from Python's import cache
    modules_to_remove = [
        'azure_modules_dashboard',
        'gcp_modules_dashboard',
        'components_sidebar',
        'azure_theme',
        'gcp_theme',
        'aws_theme',
        'components_navigation'
    ]
    
    removed = []
    for module in modules_to_remove:
        if module in sys.modules:
            del sys.modules[module]
            removed.append(module)
    
    st.success(f"✅ Cleared caches and unloaded {len(removed)} modules!")
    st.info("👉 **Next step:** Go back to Dashboard and check if formatting is fixed")
    
    st.markdown("---")
    st.markdown("**Modules removed from cache:**")
    for m in removed:
        st.caption(f"  ✓ {m}")

st.markdown("---")

st.markdown("""
### 🔍 Still not working?

Try these in order:

1. **Close this tab completely**
2. **Reopen your app URL** in a new browser tab
3. **Hard refresh** the page (Ctrl+F5 or Cmd+Shift+R)
4. **Try incognito/private browsing mode**
5. **Check the diagnostic page** to verify file versions

If STILL not working after all this:
- The GitHub files might not have uploaded correctly
- Try uploading the files again
- Or use the diagnostic tool to verify what's actually running
""")
