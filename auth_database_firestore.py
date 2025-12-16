"""
Firestore Database Operations for User Management
Serverless NoSQL database with real-time sync
"""

import streamlit as st
from typing import Optional, Dict, Any, List
from datetime import datetime
import json
import os

# Try to import Firestore libraries
try:
    from google.cloud import firestore
    from google.oauth2 import service_account
    import google.auth
    FIRESTORE_AVAILABLE = True
except ImportError:
    FIRESTORE_AVAILABLE = False
    st.warning("⚠️ Firestore libraries not installed. Run: pip install google-cloud-firestore")


class FirestoreManager:
    """Firestore database operations manager"""
    
    def __init__(self):
        """Initialize Firestore connection"""
        self.db = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize Firestore connection"""
        if not FIRESTORE_AVAILABLE:
            return
        
        try:
            # Try to get credentials from Streamlit secrets
            if 'gcp' in st.secrets and 'service_account' in st.secrets['gcp']:
                # Load from Streamlit secrets (JSON format)
                credentials_dict = dict(st.secrets['gcp']['service_account'])
                credentials = service_account.Credentials.from_service_account_info(credentials_dict)
                project_id = credentials_dict.get('project_id')
                self.db = firestore.Client(project=project_id, credentials=credentials)
            elif os.path.exists('firestore-key.json'):
                # Load from service account key file
                credentials = service_account.Credentials.from_service_account_file('firestore-key.json')
                self.db = firestore.Client(credentials=credentials)
            else:
                # Try default credentials (works in GCP environments)
                self.db = firestore.Client()
            
            st.success("✅ Firestore connected successfully")
        except Exception as e:
            st.error(f"❌ Firestore connection failed: {str(e)}")
            st.info("""
            **Setup Firestore:**
            
            1. Create a Google Cloud project
            2. Enable Firestore API
            3. Create a service account with Firestore permissions
            4. Download the JSON key file
            5. Add to Streamlit secrets (see documentation)
            """)
    
    def _get_collection(self, collection_name: str):
        """Get Firestore collection"""
        if not self.db:
            return None
        return self.db.collection(collection_name)
    
    # User operations
    
    def create_or_update_user(self, user_info: Dict[str, Any]) -> bool:
        """Create or update user in Firestore"""
        if not self.db:
            return False
        
        try:
            users_ref = self._get_collection('users')
            user_id = user_info['id']
            
            # Check if user exists
            user_doc = users_ref.document(user_id).get()
            
            user_data = {
                'id': user_info['id'],
                'email': user_info.get('email'),
                'name': user_info.get('name'),
                'given_name': user_info.get('given_name'),
                'surname': user_info.get('surname'),
                'job_title': user_info.get('job_title'),
                'department': user_info.get('department'),
                'office_location': user_info.get('office_location'),
                'last_login': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            }
            
            if user_doc.exists:
                # Update existing user
                users_ref.document(user_id).update(user_data)
            else:
                # Create new user with default role
                user_data['role'] = 'viewer'
                user_data['is_active'] = True
                user_data['created_at'] = firestore.SERVER_TIMESTAMP
                users_ref.document(user_id).set(user_data)
            
            return True
        except Exception as e:
            st.error(f"Failed to save user: {str(e)}")
            return False
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID from Firestore"""
        if not self.db:
            return None
        
        try:
            users_ref = self._get_collection('users')
            user_doc = users_ref.document(user_id).get()
            
            if user_doc.exists:
                user_data = user_doc.to_dict()
                # Convert Firestore timestamps to ISO format
                for field in ['created_at', 'updated_at', 'last_login']:
                    if field in user_data and user_data[field]:
                        user_data[field] = user_data[field].isoformat()
                return user_data
            return None
        except Exception as e:
            st.error(f"Failed to get user: {str(e)}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email from Firestore"""
        if not self.db:
            return None
        
        try:
            users_ref = self._get_collection('users')
            # Query by email
            query = users_ref.where('email', '==', email).limit(1)
            docs = query.stream()
            
            for doc in docs:
                user_data = doc.to_dict()
                # Convert timestamps
                for field in ['created_at', 'updated_at', 'last_login']:
                    if field in user_data and user_data[field]:
                        user_data[field] = user_data[field].isoformat()
                return user_data
            
            return None
        except Exception as e:
            st.error(f"Failed to get user: {str(e)}")
            return None
    
    def update_user_role(self, user_id: str, role: str) -> bool:
        """Update user role in Firestore"""
        if not self.db:
            return False
        
        try:
            users_ref = self._get_collection('users')
            users_ref.document(user_id).update({
                'role': role,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            return True
        except Exception as e:
            st.error(f"Failed to update role: {str(e)}")
            return False
    
    def get_all_users(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """Get all users from Firestore"""
        if not self.db:
            return []
        
        try:
            users_ref = self._get_collection('users')
            query = users_ref
            
            if active_only:
                query = query.where('is_active', '==', True)
            
            users = []
            for doc in query.stream():
                user_data = doc.to_dict()
                # Convert timestamps
                if 'last_login' in user_data and user_data['last_login']:
                    user_data['last_login'] = user_data['last_login'].isoformat()
                
                users.append({
                    'id': user_data.get('id'),
                    'email': user_data.get('email'),
                    'name': user_data.get('name'),
                    'role': user_data.get('role'),
                    'department': user_data.get('department'),
                    'last_login': user_data.get('last_login')
                })
            
            return users
        except Exception as e:
            st.error(f"Failed to get users: {str(e)}")
            return []
    
    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate user in Firestore"""
        if not self.db:
            return False
        
        try:
            users_ref = self._get_collection('users')
            users_ref.document(user_id).update({
                'is_active': False,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            return True
        except Exception as e:
            st.error(f"Failed to deactivate user: {str(e)}")
            return False
    
    # User preferences operations
    
    def get_user_preferences(self, user_id: str) -> Dict[str, Any]:
        """Get user preferences from Firestore"""
        if not self.db:
            return self._default_preferences()
        
        try:
            prefs_ref = self._get_collection('user_preferences')
            prefs_doc = prefs_ref.document(user_id).get()
            
            if prefs_doc.exists:
                prefs_data = prefs_doc.to_dict()
                return {
                    'theme': prefs_data.get('theme', 'light'),
                    'default_cloud': prefs_data.get('default_cloud', 'aws'),
                    'notifications_enabled': prefs_data.get('notifications_enabled', True),
                    'dashboard_layout': prefs_data.get('dashboard_layout', 'default')
                }
            
            return self._default_preferences()
        except Exception as e:
            st.error(f"Failed to get preferences: {str(e)}")
            return self._default_preferences()
    
    def save_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> bool:
        """Save user preferences to Firestore"""
        if not self.db:
            return False
        
        try:
            prefs_ref = self._get_collection('user_preferences')
            prefs_data = {
                'user_id': user_id,
                'theme': preferences.get('theme', 'light'),
                'default_cloud': preferences.get('default_cloud', 'aws'),
                'notifications_enabled': preferences.get('notifications_enabled', True),
                'dashboard_layout': preferences.get('dashboard_layout', 'default'),
                'updated_at': firestore.SERVER_TIMESTAMP
            }
            
            # Upsert (set with merge)
            prefs_ref.document(user_id).set(prefs_data, merge=True)
            return True
        except Exception as e:
            st.error(f"Failed to save preferences: {str(e)}")
            return False
    
    # Audit log operations
    
    def log_event(self, user_id: str, event_type: str, event_data: Dict[str, Any],
                   ip_address: str = None, user_agent: str = None) -> bool:
        """Log audit event to Firestore"""
        if not self.db:
            return False
        
        try:
            audit_ref = self._get_collection('audit_log')
            log_entry = {
                'user_id': user_id,
                'event_type': event_type,
                'event_data': event_data,  # Firestore supports nested objects
                'ip_address': ip_address or 'unknown',
                'user_agent': user_agent or 'unknown',
                'timestamp': firestore.SERVER_TIMESTAMP
            }
            
            # Auto-generate document ID
            audit_ref.add(log_entry)
            return True
        except Exception as e:
            st.error(f"Failed to log event: {str(e)}")
            return False
    
    def get_audit_logs(self, user_id: str = None, event_type: str = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit logs from Firestore"""
        if not self.db:
            return []
        
        try:
            audit_ref = self._get_collection('audit_log')
            query = audit_ref
            
            # Apply filters
            if user_id:
                query = query.where('user_id', '==', user_id)
            if event_type:
                query = query.where('event_type', '==', event_type)
            
            # Order by timestamp descending and limit
            query = query.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
            
            logs = []
            for doc in query.stream():
                log_data = doc.to_dict()
                # Convert timestamp
                if 'timestamp' in log_data and log_data['timestamp']:
                    log_data['timestamp'] = log_data['timestamp'].isoformat()
                
                logs.append({
                    'user_id': log_data.get('user_id'),
                    'event_type': log_data.get('event_type'),
                    'event_data': log_data.get('event_data', {}),
                    'ip_address': log_data.get('ip_address'),
                    'timestamp': log_data.get('timestamp')
                })
            
            return logs
        except Exception as e:
            st.error(f"Failed to get audit logs: {str(e)}")
            return []
    
    def get_user_stats(self) -> Dict[str, Any]:
        """Get user statistics from Firestore"""
        if not self.db:
            return {}
        
        try:
            users_ref = self._get_collection('users')
            
            # Total users
            total_users = len(list(users_ref.stream()))
            
            # Active users
            active_users = len(list(users_ref.where('is_active', '==', True).stream()))
            
            # Users by role
            roles = {}
            for doc in users_ref.stream():
                role = doc.to_dict().get('role', 'viewer')
                roles[role] = roles.get(role, 0) + 1
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': total_users - active_users,
                'users_by_role': roles
            }
        except Exception as e:
            st.error(f"Failed to get stats: {str(e)}")
            return {}
    
    def _default_preferences(self) -> Dict[str, Any]:
        """Get default preferences"""
        return {
            'theme': 'light',
            'default_cloud': 'aws',
            'notifications_enabled': True,
            'dashboard_layout': 'default'
        }
    
    # Batch operations (efficient for Firestore)
    
    def batch_update_users(self, updates: List[Dict[str, Any]]) -> bool:
        """Batch update multiple users (efficient Firestore operation)"""
        if not self.db:
            return False
        
        try:
            batch = self.db.batch()
            users_ref = self._get_collection('users')
            
            for update in updates:
                user_id = update.pop('id')
                doc_ref = users_ref.document(user_id)
                update['updated_at'] = firestore.SERVER_TIMESTAMP
                batch.update(doc_ref, update)
            
            batch.commit()
            return True
        except Exception as e:
            st.error(f"Failed to batch update: {str(e)}")
            return False
    
    # Real-time listeners (Firestore feature)
    
    def listen_to_user_changes(self, user_id: str, callback):
        """Listen to real-time user changes (Firestore feature)"""
        if not self.db:
            return None
        
        try:
            users_ref = self._get_collection('users')
            doc_ref = users_ref.document(user_id)
            
            # Create a real-time listener
            def on_snapshot(doc_snapshot, changes, read_time):
                for doc in doc_snapshot:
                    callback(doc.to_dict())
            
            # Start listening
            return doc_ref.on_snapshot(on_snapshot)
        except Exception as e:
            st.error(f"Failed to create listener: {str(e)}")
            return None


# Initialize Firestore manager
def get_firestore_manager() -> FirestoreManager:
    """Get or create Firestore manager"""
    if 'firestore_manager' not in st.session_state:
        st.session_state.firestore_manager = FirestoreManager()
    return st.session_state.firestore_manager


# Alias for compatibility with existing code
def get_database_manager() -> FirestoreManager:
    """Get database manager (Firestore)"""
    return get_firestore_manager()
