#!/usr/bin/env python3
"""
Test script to verify eks_modernization module works correctly
Run this before deploying to catch issues early
"""

import sys
import os

def test_import():
    """Test if module can be imported"""
    print("=" * 60)
    print("TEST 1: Module Import")
    print("=" * 60)
    
    try:
        import eks_modernization
        print("✅ SUCCESS: eks_modernization module imported")
        return True
    except ImportError as e:
        print(f"❌ FAILED: Cannot import module")
        print(f"   Error: {e}")
        return False

def test_function_exists():
    """Test if required function exists"""
    print("\n" + "=" * 60)
    print("TEST 2: Function Exists")
    print("=" * 60)
    
    try:
        from eks_modernization import render_eks_modernization_tab
        print("✅ SUCCESS: render_eks_modernization_tab function found")
        print(f"   Function: {render_eks_modernization_tab}")
        return True
    except ImportError as e:
        print(f"❌ FAILED: Function not found")
        print(f"   Error: {e}")
        return False

def test_function_callable():
    """Test if function is callable"""
    print("\n" + "=" * 60)
    print("TEST 3: Function Callable")
    print("=" * 60)
    
    try:
        from eks_modernization import render_eks_modernization_tab
        if callable(render_eks_modernization_tab):
            print("✅ SUCCESS: Function is callable")
            return True
        else:
            print("❌ FAILED: Function exists but is not callable")
            return False
    except Exception as e:
        print(f"❌ FAILED: Cannot verify callable")
        print(f"   Error: {e}")
        return False

def test_module_attributes():
    """List all available attributes in module"""
    print("\n" + "=" * 60)
    print("TEST 4: Module Attributes")
    print("=" * 60)
    
    try:
        import eks_modernization
        attrs = dir(eks_modernization)
        
        print("📋 Available in module:")
        for attr in attrs:
            if not attr.startswith('_'):
                print(f"   • {attr}")
        
        if 'render_eks_modernization_tab' in attrs:
            print("\n✅ SUCCESS: render_eks_modernization_tab is available")
            return True
        else:
            print("\n❌ FAILED: render_eks_modernization_tab not in module")
            return False
    except Exception as e:
        print(f"❌ FAILED: Cannot list attributes")
        print(f"   Error: {e}")
        return False

def check_file_location():
    """Check if file exists in expected location"""
    print("\n" + "=" * 60)
    print("INFO: File Location Check")
    print("=" * 60)
    
    possible_locations = [
        './eks_modernization.py',
        '/mount/src/awswaf/eks_modernization.py',
        '../eks_modernization.py',
    ]
    
    found = False
    for location in possible_locations:
        if os.path.exists(location):
            print(f"✅ Found: {location}")
            print(f"   Size: {os.path.getsize(location)} bytes")
            found = True
        else:
            print(f"❌ Not found: {location}")
    
    if not found:
        print("\n⚠️  WARNING: File not found in common locations")
        print("   Make sure eks_modernization.py is in your project directory")
    
    return found

def check_dependencies():
    """Check if required dependencies are installed"""
    print("\n" + "=" * 60)
    print("INFO: Dependencies Check")
    print("=" * 60)
    
    dependencies = ['streamlit', 'pandas', 'plotly', 'boto3']
    
    all_installed = True
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"✅ {dep:15s} - installed")
        except ImportError:
            print(f"❌ {dep:15s} - NOT INSTALLED")
            all_installed = False
    
    if not all_installed:
        print("\n⚠️  WARNING: Some dependencies missing")
        print("   Run: pip install -r requirements.txt")
    
    return all_installed

def main():
    """Run all tests"""
    print("\n" + "🔍" * 30)
    print("EKS MODERNIZATION MODULE - VERIFICATION TESTS")
    print("🔍" * 30 + "\n")
    
    # Check file location first
    check_file_location()
    
    # Check dependencies
    check_dependencies()
    
    # Run import tests
    results = []
    results.append(("Import module", test_import()))
    results.append(("Function exists", test_function_exists()))
    results.append(("Function callable", test_function_callable()))
    results.append(("Module attributes", test_module_attributes()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:8s} - {test_name}")
    
    print("\n" + "-" * 60)
    print(f"Results: {passed}/{total} tests passed")
    print("-" * 60)
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        print("   Your module is ready to use.")
        return 0
    else:
        print("\n⚠️  SOME TESTS FAILED")
        print("   Please check the errors above and fix them.")
        print("\n💡 Quick fixes:")
        print("   1. Make sure eks_modernization.py is in your project directory")
        print("   2. Run: pip install -r requirements.txt")
        print("   3. Clear Python cache: rm -rf __pycache__")
        print("   4. Use V2 module: cp eks_modernization_v2.py eks_modernization.py")
        return 1

if __name__ == "__main__":
    sys.exit(main())
