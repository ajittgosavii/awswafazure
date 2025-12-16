"""
Session Manager - Global State Management
"""

import streamlit as st
from typing import Any, Optional, List, Dict
from datetime import datetime

class SessionManager:
    """Centralized session state management"""
    
    @staticmethod
    def initialize():
        """Initialize all session state variables"""
        
        # App state
        if 'initialized' not in st.session_state:
            st.session_state.initialized = True
            st.session_state.app_start_time = datetime.now()
        
        # Account filters
        if 'selected_accounts' not in st.session_state:
            st.session_state.selected_accounts = 'all'
        
        if 'selected_regions' not in st.session_state:
            st.session_state.selected_regions = 'all'
        
        if 'selected_environment' not in st.session_state:
            st.session_state.selected_environment = 'all'
        
        # Navigation
        if 'current_module' not in st.session_state:
            st.session_state.current_module = 'dashboard'
        
        # Data refresh
        if 'last_refresh' not in st.session_state:
            st.session_state.last_refresh = datetime.now()
        
        # User preferences
        if 'page_size' not in st.session_state:
            st.session_state.page_size = 50
        
        if 'theme' not in st.session_state:
            st.session_state.theme = 'light'
        
        # Cache control
        if 'force_refresh' not in st.session_state:
            st.session_state.force_refresh = False
    
    @staticmethod
    def get(key: str, default: Any = None) -> Any:
        """Get value from session state"""
        return st.session_state.get(key, default)
    
    @staticmethod
    def set(key: str, value: Any):
        """Set value in session state"""
        st.session_state[key] = value
    
    @staticmethod
    def get_selected_accounts() -> List[str]:
        """Get list of selected account IDs"""
        if st.session_state.selected_accounts == 'all':
            from config_settings import AppConfig
            accounts = AppConfig.load_aws_accounts()
            return [acc.account_id for acc in accounts if acc.status == 'active']
        else:
            return [st.session_state.selected_accounts]
    
    @staticmethod
    def get_selected_regions() -> List[str]:
        """Get list of selected regions"""
        if st.session_state.selected_regions == 'all':
            from config_settings import AppConfig
            return AppConfig.DEFAULT_REGIONS
        else:
            return [st.session_state.selected_regions]
    
    @staticmethod
    def get_active_account_count() -> int:
        """Get count of active connected accounts"""
        from config_settings import AppConfig
        accounts = AppConfig.load_aws_accounts()
        return len([acc for acc in accounts if acc.status == 'active'])
    
    @staticmethod
    def trigger_refresh():
        """Trigger data refresh"""
        st.session_state.force_refresh = True
        st.session_state.last_refresh = datetime.now()
    
    @staticmethod
    def clear_refresh_flag():
        """Clear refresh flag"""
        st.session_state.force_refresh = False
    
    @staticmethod
    def is_refresh_needed() -> bool:
        """Check if data refresh is needed"""
        return st.session_state.get('force_refresh', False)
