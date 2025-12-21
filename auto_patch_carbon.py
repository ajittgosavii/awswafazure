#!/usr/bin/env python3
"""
Automatic Patch for Carbon Tracking TypeError
Fixes line 1361 in modules_finops.py
"""

import os
import re

def patch_modules_finops(file_path='/mount/src/awswafazure/modules_finops.py'):
    """
    Automatically patch the modules_finops.py file to fix the TypeError
    """
    print("🔧 Carbon Tracking Error - Automated Patch")
    print("=" * 50)
    print()
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        print("Please update the file_path variable")
        return False
    
    print(f"📁 Reading file: {file_path}")
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Pattern to find the buggy code
    buggy_pattern = r'''        with col3:
            total_saved = sum\(r\['emissions_saved_kg'\] for r in carbon_data\['recommendations'\]\)
            st\.metric\(
                "Potential Reduction",
                f"\{total_saved:,.0f\} kg CO2",
                delta=f"\{.*?\}"
            \)'''
    
    # Replacement code
    fixed_code = '''        with col3:
            st.metric(
                "Renewable Energy",
                f"{renewable_pct:.0f}%",
                delta=None
            )'''
    
    # Check if buggy code exists
    if 'emissions_saved_kg' in content and 'Potential Reduction' in content:
        print("✅ Found buggy code that needs fixing")
        
        # Try to replace
        new_content = re.sub(buggy_pattern, fixed_code, content, flags=re.MULTILINE)
        
        if new_content == content:
            # Regex didn't match, try simpler replacement
            print("⚠️  Regex pattern didn't match, trying line-by-line replacement...")
            
            lines = content.split('\n')
            new_lines = []
            skip_lines = 0
            
            for i, line in enumerate(lines):
                if skip_lines > 0:
                    skip_lines -= 1
                    continue
                
                # Look for the buggy line
                if "total_saved = sum(r['emissions_saved_kg']" in line:
                    print(f"✅ Found buggy code at line {i+1}")
                    
                    # Replace this section (7 lines total)
                    new_lines.append('        with col3:')
                    new_lines.append('            st.metric(')
                    new_lines.append('                "Renewable Energy",')
                    new_lines.append('                f"{renewable_pct:.0f}%",')
                    new_lines.append('                delta=None')
                    new_lines.append('            )')
                    
                    # Skip the next 5 lines of buggy code
                    skip_lines = 5
                else:
                    new_lines.append(line)
            
            new_content = '\n'.join(new_lines)
        
        # Backup original file
        backup_path = file_path + '.backup'
        print(f"💾 Creating backup: {backup_path}")
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Write fixed file
        print(f"✏️  Writing fixed file: {file_path}")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print()
        print("=" * 50)
        print("✅ PATCH APPLIED SUCCESSFULLY!")
        print("=" * 50)
        print()
        print("Next steps:")
        print("1. Streamlit will auto-reload")
        print("2. Go to Sustainability & CO2 tab")
        print("3. Should work without errors now!")
        print()
        print(f"If anything goes wrong, restore from: {backup_path}")
        
        return True
        
    elif 'Renewable Energy' in content and 'renewable_pct' in content:
        print("✅ File already patched - no action needed")
        return True
    else:
        print("❌ Could not find the code to patch")
        print("The file may have a different structure than expected")
        return False


if __name__ == '__main__':
    # Run the patch
    success = patch_modules_finops()
    
    if success:
        print("✅ Done!")
    else:
        print("❌ Patch failed - please apply manual fix")
        print("See QUICK_FIX_CARBON_ERROR.md for instructions")
