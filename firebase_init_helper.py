"""
Firebase Initialization Helper
Initializes Firebase/Firestore if not already initialized
Works with both firebase_auth_module and standalone setup
"""

import streamlit as st
from typing import Tuple

def initialize_firebase_if_needed() -> Tuple[bool, str]:
    """
    Initialize Firebase if not already initialized
    
    Returns:
        (success, message)
    """
    
    # Check if already initialized via firebase_auth_module
    if st.session_state.get('firebase_initialized', False):
        return True, "Firebase already initialized"
    
    # Try to initialize from firebase_auth_module if available
    try:
        from firebase_auth_module import firebase_manager
        
        if firebase_manager.initialized and firebase_manager.db:
            st.session_state.firebase_initialized = True
            return True, "Firebase connected via firebase_manager"
        
        # Firebase manager exists but not initialized, try to initialize it
        if 'firebase' in st.secrets:
            config = {
                'service_account_key': dict(st.secrets['firebase'])
            }
            success, message = firebase_manager.initialize_firebase(config)
            if success:
                st.session_state.firebase_initialized = True
                return True, message
            else:
                return False, f"Firebase manager initialization failed: {message}"
    
    except ImportError:
        # firebase_auth_module not available, try direct initialization
        pass
    except Exception as e:
        print(f"Error initializing via firebase_manager: {e}")
    
    # Try direct initialization from secrets
    if 'firebase' in st.secrets:
        try:
            import firebase_admin
            from firebase_admin import credentials, firestore
            
            # Check if already initialized
            if firebase_admin._apps:
                st.session_state.firebase_initialized = True
                return True, "Firebase already initialized (direct)"
            
            # Initialize Firebase
            cred = credentials.Certificate(dict(st.secrets['firebase']))
            firebase_admin.initialize_app(cred)
            st.session_state.firebase_initialized = True
            return True, "Firebase initialized from secrets"
            
        except Exception as e:
            return False, f"Firebase initialization failed: {str(e)}"
    
    # No Firebase configuration available
    return False, "Firebase secrets not configured"


def get_firestore_client():
    """
    Get Firestore client (tries multiple methods)
    
    Returns:
        Firestore client or None
    """
    
    # Method 1: Try to get from firebase_manager
    try:
        from firebase_auth_module import firebase_manager
        if firebase_manager and firebase_manager.db:
            return firebase_manager.db
    except:
        pass
    
    # Method 2: Try to get from firebase_admin
    try:
        import firebase_admin
        from firebase_admin import firestore
        
        if firebase_admin._apps:
            return firestore.client()
    except:
        pass
    
    return None
