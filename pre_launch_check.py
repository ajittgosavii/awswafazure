#!/usr/bin/env python3
"""
CloudIDP Pre-Launch Verification
Checks all requirements before launching CloudIDP
"""

import os
import sys

def check_mark(condition):
    return "✅" if condition else "❌"

def check_directory():
    """Check if we're in the right directory"""
    files_needed = ['streamlit_app.py', 'app.py']
    for file in files_needed:
        if os.path.exists(file):
            return True, f"Found {file}"
    return False, "Not in CloudIDP directory (no streamlit_app.py or app.py found)"

def check_secrets_file():
    """Check if secrets.toml exists"""
    path = '.streamlit/secrets.toml'
    if os.path.exists(path):
        return True, f"Found {path}"
    return False, f"Missing {path}"

def check_secrets_content():
    """Check secrets.toml has required content"""
    path = '.streamlit/secrets.toml'
    
    if not os.path.exists(path):
        return False, "secrets.toml doesn't exist"
    
    try:
        import toml
    except ImportError:
        os.system("pip install toml -q")
        import toml
    
    try:
        config = toml.load(path)
        
        # Check [aws] section
        if 'aws' not in config:
            return False, "Missing [aws] section"
        
        # Check required keys
        required = ['management_access_key_id', 'management_secret_access_key']
        for key in required:
            if key not in config['aws']:
                return False, f"Missing {key} in [aws] section"
            
            value = config['aws'][key]
            if not value or value == "your-secret-key-here" or value == "paste-your-secret-key-here":
                return False, f"{key} is not set (placeholder value)"
        
        # Check accounts
        if 'accounts' not in config['aws']:
            return False, "Missing [aws.accounts] section"
        
        if len(config['aws']['accounts']) == 0:
            return False, "No accounts configured"
        
        return True, f"Configuration valid, {len(config['aws']['accounts'])} account(s) found"
        
    except Exception as e:
        return False, f"Error reading secrets.toml: {str(e)}"

def check_aws_credentials():
    """Check if AWS credentials work"""
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return None, "boto3 not installed (will be installed when CloudIDP starts)"
    
    try:
        import toml
        config = toml.load('.streamlit/secrets.toml')
        
        access_key = config['aws']['management_access_key_id']
        secret_key = config['aws']['management_secret_access_key']
        
        sts = boto3.client(
            'sts',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        
        identity = sts.get_caller_identity()
        account = identity['Account']
        
        return True, f"Credentials valid, Account: {account}"
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return False, f"AWS Error: {error_code}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def check_streamlit():
    """Check if streamlit is installed"""
    try:
        import streamlit
        return True, f"Streamlit {streamlit.__version__} installed"
    except ImportError:
        return False, "Streamlit not installed (run: pip install streamlit)"

def main():
    print("=" * 70)
    print("CloudIDP Pre-Launch Verification")
    print("=" * 70)
    print()
    
    checks = []
    
    # Check directory
    is_ok, msg = check_directory()
    checks.append(('Directory', is_ok, msg))
    
    # Check secrets file exists
    is_ok, msg = check_secrets_file()
    checks.append(('Secrets File', is_ok, msg))
    
    # Check secrets content
    is_ok, msg = check_secrets_content()
    checks.append(('Configuration', is_ok, msg))
    
    # Check AWS credentials
    is_ok, msg = check_aws_credentials()
    if is_ok is not None:
        checks.append(('AWS Connection', is_ok, msg))
    
    # Check Streamlit
    is_ok, msg = check_streamlit()
    checks.append(('Streamlit', is_ok, msg))
    
    # Print results
    all_passed = True
    for name, passed, message in checks:
        status = check_mark(passed)
        print(f"{status} {name:20} {message}")
        if not passed:
            all_passed = False
    
    print()
    print("=" * 70)
    
    if all_passed:
        print("✅ ALL CHECKS PASSED - Ready to launch CloudIDP!")
        print()
        print("Launch CloudIDP with:")
        print("  streamlit run streamlit_app.py")
        print()
        print("Or if that doesn't work:")
        print("  streamlit run app.py")
        print()
    else:
        print("❌ Some checks failed - Fix issues above before launching")
        print()
        print("Common fixes:")
        print("  • Not in right directory: cd cloudidps_enhanced")
        print("  • Missing secrets.toml: Create .streamlit/secrets.toml")
        print("  • Bad credentials: Check secrets.toml matches AWS CLI config")
        print("  • Missing Streamlit: pip install streamlit")
        print()
    
    print("=" * 70)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
