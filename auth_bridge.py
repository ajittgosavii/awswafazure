"""
Authentication Bridge Module
============================
Provides unified authentication interface supporting:
- Azure AD / Entra ID (Primary - Enterprise SSO)
- Firebase Authentication (Legacy support)
- Local Authentication (Development/Fallback)

This module acts as a bridge between the application and authentication backends,
allowing seamless switching between Azure AD and Firebase.

Version: 1.0.0
"""

import streamlit as st
from datetime import datetime
from typing import Optional, Tuple
import os

# Try Azure AD first (preferred for enterprise)
AZURE_AD_AVAILABLE = False
try:
    from auth_azure_entra import (
        AzureADAuthManager,
        User as AzureUser,
        UserRole,
        SessionManager as AzureSessionManager,
        get_auth_manager as get_azure_auth_manager,
        render_login_page as render_azure_login,
        render_user_menu as render_azure_user_menu,
        render_admin_panel as render_azure_admin_panel,
        check_tab_access,
        ROLE_PERMISSIONS,
        TAB_ACCESS,
    )
    AZURE_AD_AVAILABLE = True
except ImportError as e:
    print(f"Azure AD module not available: {e}")

# Try Firebase as fallback
FIREBASE_AVAILABLE = False
try:
    from sso_admin_manager_firebase import (
        SSOAuthManager as FirebaseAuthManager,
        User as FirebaseUser,
        UserRole as FirebaseUserRole,
        SessionManager as FirebaseSessionManager,
        get_auth_manager as get_firebase_auth_manager,
        render_login_page as render_firebase_login,
        render_user_menu as render_firebase_user_menu,
        render_admin_panel as render_firebase_admin_panel,
    )
    FIREBASE_AVAILABLE = True
except ImportError:
    pass


def get_auth_backend() -> str:
    """Determine which authentication backend to use"""
    # Check for Azure AD configuration
    try:
        azure_config = st.secrets.get("azure_ad", {})
        if azure_config.get("tenant_id") and azure_config.get("client_id"):
            return "azure_ad"
    except Exception:
        pass
    
    # Check for Firebase configuration
    try:
        firebase_config = st.secrets.get("firebase", {})
        if firebase_config.get("project_id"):
            return "firebase"
    except Exception:
        pass
    
    # Default to local/Azure AD (with local fallback)
    return "azure_ad"


def get_auth_manager():
    """Get the appropriate auth manager based on configuration"""
    backend = get_auth_backend()
    
    if backend == "azure_ad" and AZURE_AD_AVAILABLE:
        return get_azure_auth_manager()
    elif backend == "firebase" and FIREBASE_AVAILABLE:
        return get_firebase_auth_manager()
    elif AZURE_AD_AVAILABLE:
        return get_azure_auth_manager()
    elif FIREBASE_AVAILABLE:
        return get_firebase_auth_manager()
    else:
        raise RuntimeError("No authentication backend available")


class SessionManager:
    """Unified session manager"""
    
    @staticmethod
    def login(user):
        """Login user"""
        if AZURE_AD_AVAILABLE:
            AzureSessionManager.login(user)
        elif FIREBASE_AVAILABLE:
            FirebaseSessionManager.login(user)
    
    @staticmethod
    def logout():
        """Logout user"""
        if AZURE_AD_AVAILABLE:
            AzureSessionManager.logout()
        elif FIREBASE_AVAILABLE:
            FirebaseSessionManager.logout()
    
    @staticmethod
    def is_authenticated() -> bool:
        """Check if user is authenticated"""
        if AZURE_AD_AVAILABLE:
            return AzureSessionManager.is_authenticated()
        elif FIREBASE_AVAILABLE:
            return FirebaseSessionManager.is_authenticated()
        return False
    
    @staticmethod
    def get_current_user():
        """Get current user"""
        if AZURE_AD_AVAILABLE:
            return AzureSessionManager.get_current_user()
        elif FIREBASE_AVAILABLE:
            return FirebaseSessionManager.get_current_user()
        return None
    
    @staticmethod
    def has_permission(permission: str) -> bool:
        """Check permission"""
        if AZURE_AD_AVAILABLE:
            return AzureSessionManager.has_permission(permission)
        elif FIREBASE_AVAILABLE:
            return FirebaseSessionManager.has_permission(permission)
        return False


def render_login_page():
    """Render appropriate login page"""
    backend = get_auth_backend()
    
    if backend == "azure_ad" and AZURE_AD_AVAILABLE:
        render_azure_login()
    elif backend == "firebase" and FIREBASE_AVAILABLE:
        render_firebase_login()
    elif AZURE_AD_AVAILABLE:
        render_azure_login()
    elif FIREBASE_AVAILABLE:
        render_firebase_login()
    else:
        st.error("No authentication backend available")


def render_user_menu():
    """Render user menu"""
    if AZURE_AD_AVAILABLE:
        render_azure_user_menu()
    elif FIREBASE_AVAILABLE:
        render_firebase_user_menu()


def render_admin_panel():
    """Render admin panel"""
    if AZURE_AD_AVAILABLE:
        render_azure_admin_panel()
    elif FIREBASE_AVAILABLE:
        render_firebase_admin_panel()


# Export UserRole from the available backend
if AZURE_AD_AVAILABLE:
    from auth_azure_entra import UserRole, User, check_tab_access
else:
    # Define fallback
    from enum import Enum
    class UserRole(Enum):
        GUEST = 0
        VIEWER = 1
        USER = 2
        MANAGER = 3
        ADMIN = 4
        SUPER_ADMIN = 5
    
    def check_tab_access(tab_name: str) -> bool:
        return True


__all__ = [
    'get_auth_manager',
    'get_auth_backend',
    'SessionManager',
    'render_login_page',
    'render_user_menu', 
    'render_admin_panel',
    'UserRole',
    'check_tab_access',
    'AZURE_AD_AVAILABLE',
    'FIREBASE_AVAILABLE',
]
