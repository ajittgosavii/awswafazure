"""
Fix streamlit_app.py to import the correct class names
"""

# Read current streamlit_app.py
with open('streamlit_app.py', 'r') as f:
    content = f.read()

# Fix imports
replacements = {
    # EKS Module
    'from eks_modernization_module import EKSModernizationModule': 
    'from eks_modernization_module import EKSDesignWizard as EKSModernizationModule',
    
    # FinOps Module  
    'from finops_module import FinOpsModule':
    'from finops_module import AWSCostExplorerIntegration as FinOpsModule',
    
    # Security Module
    'from modules_security_compliance import SecurityComplianceModule':
    'from modules_security_compliance import UnifiedSecurityComplianceModule as SecurityComplianceModule',
}

for old, new in replacements.items():
    if old in content:
        content = content.replace(old, new)
        print(f"✅ Fixed: {old.split(' import ')[1]}")

# Write back
with open('streamlit_app.py', 'w') as f:
    f.write(content)

print("\n✅ streamlit_app.py updated with correct imports!")

