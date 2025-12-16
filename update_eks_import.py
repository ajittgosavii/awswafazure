"""
Update streamlit_app.py to import EKS correctly
"""

with open('streamlit_app.py', 'r') as f:
    content = f.read()

# Replace the EKS import
old_import = 'from eks_modernization_module import EKSDesignWizard as EKSModernizationModule'
new_import = 'from eks_modernization_module import EKSModernizationModule'

if old_import in content:
    content = content.replace(old_import, new_import)
    print("✅ Updated EKS import to use EKSModernizationModule directly")
elif 'from eks_modernization_module import' in content:
    # Find and replace any EKS import
    import re
    content = re.sub(
        r'from eks_modernization_module import \w+( as \w+)?',
        'from eks_modernization_module import EKSModernizationModule',
        content
    )
    print("✅ Fixed EKS import pattern")
else:
    print("⚠️ EKS import not found, no changes made")

with open('streamlit_app.py', 'w') as f:
    f.write(content)

print("✅ streamlit_app.py updated!")

