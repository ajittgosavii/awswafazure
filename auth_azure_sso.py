"""
Stub for auth_azure_sso - AWS-only version
Provides no-op decorators for compatibility
"""

def require_permission(permission):
    """No-op decorator for AWS-only version"""
    def decorator(func):
        return func
    return decorator

def check_permission(permission):
    """Always returns True in AWS-only version"""
    return True
