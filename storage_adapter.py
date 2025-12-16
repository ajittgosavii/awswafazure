"""
Storage Adapter - Unified interface for Session State and Firebase
Allows seamless switching between in-memory and persistent storage
"""

import streamlit as st
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

# ============================================================================
# FIREBASE INITIALIZATION
# ============================================================================

@st.cache_resource
def init_firebase():
    """Initialize Firebase (cached to run once)"""
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
        
        # Check if already initialized
        if firebase_admin._apps:
            return firestore.client()
        
        # Load credentials from Streamlit secrets
        if 'firebase' in st.secrets:
            cred_dict = dict(st.secrets["firebase"])
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            return firestore.client()
        else:
            st.warning("⚠️ Firebase credentials not found in secrets")
            return None
            
    except ImportError:
        st.warning("⚠️ Firebase SDK not installed. Run: pip install firebase-admin")
        return None
    except Exception as e:
        st.error(f"⚠️ Firebase initialization error: {str(e)}")
        return None

# ============================================================================
# STORAGE ADAPTER
# ============================================================================

class DesignStorageAdapter:
    """
    Unified storage interface for architecture designs.
    Automatically uses Firebase if available, falls back to session state.
    """
    
    def __init__(self, use_firebase: bool = True):
        """
        Initialize storage adapter
        
        Args:
            use_firebase: Try to use Firebase if available (default: True)
        """
        self.use_firebase = use_firebase
        self.db = None
        self.collection_name = 'architecture_designs'
        
        # Try to initialize Firebase
        if use_firebase:
            self.db = init_firebase()
            if self.db:
                st.success("🔥 Firebase connected - Data will persist across sessions")
            else:
                st.info("💾 Using session storage - Data will reset on browser refresh")
        
        # Initialize session state backup
        if 'designs' not in st.session_state:
            st.session_state.designs = {}
    
    @property
    def is_firebase_available(self) -> bool:
        """Check if Firebase is available and working"""
        return self.db is not None and self.use_firebase
    
    def save_design(self, design_id: str, design_data: Dict) -> bool:
        """
        Save design to storage
        
        Args:
            design_id: Unique design identifier
            design_data: Design dictionary
            
        Returns:
            bool: True if saved successfully
        """
        try:
            # Add metadata
            design_data['id'] = design_id
            design_data['updated_at'] = datetime.utcnow().isoformat()
            
            if self.is_firebase_available:
                # Save to Firebase
                doc_ref = self.db.collection(self.collection_name).document(design_id)
                doc_ref.set(design_data)
                
                # Also cache in session state for speed
                st.session_state.designs[design_id] = design_data
                
                return True
            else:
                # Save to session state only
                st.session_state.designs[design_id] = design_data
                return True
                
        except Exception as e:
            st.error(f"Error saving design: {str(e)}")
            return False
    
    def get_design(self, design_id: str) -> Optional[Dict]:
        """
        Get design by ID
        
        Args:
            design_id: Design identifier
            
        Returns:
            Design dictionary or None
        """
        try:
            if self.is_firebase_available:
                # Check session cache first
                if design_id in st.session_state.designs:
                    return st.session_state.designs[design_id]
                
                # Load from Firebase
                doc = self.db.collection(self.collection_name).document(design_id).get()
                if doc.exists:
                    design = doc.to_dict()
                    # Cache in session
                    st.session_state.designs[design_id] = design
                    return design
                return None
            else:
                # Load from session state
                return st.session_state.designs.get(design_id)
                
        except Exception as e:
            st.error(f"Error loading design: {str(e)}")
            return None
    
    def list_designs(self, 
                    status: Optional[str] = None,
                    environment: Optional[str] = None,
                    limit: int = 100) -> List[Dict]:
        """
        List designs with optional filters
        
        Args:
            status: Filter by status (e.g., 'DRAFT', 'APPROVED')
            environment: Filter by environment (e.g., 'Production')
            limit: Maximum number of results
            
        Returns:
            List of design dictionaries
        """
        try:
            if self.is_firebase_available:
                # Query Firebase
                query = self.db.collection(self.collection_name)
                
                if status:
                    query = query.where('status', '==', status)
                
                if environment:
                    query = query.where('environment', '==', environment)
                
                query = query.limit(limit).order_by('updated_at', direction=firestore.Query.DESCENDING)
                
                docs = query.stream()
                designs = [doc.to_dict() for doc in docs]
                
                # Update session cache
                for design in designs:
                    if 'id' in design:
                        st.session_state.designs[design['id']] = design
                
                return designs
            else:
                # Filter session state
                designs = list(st.session_state.designs.values())
                
                if status:
                    designs = [d for d in designs if d.get('status') == status]
                
                if environment:
                    designs = [d for d in designs if d.get('environment') == environment]
                
                # Sort by updated_at
                designs.sort(key=lambda x: x.get('updated_at', ''), reverse=True)
                
                return designs[:limit]
                
        except Exception as e:
            st.error(f"Error listing designs: {str(e)}")
            return []
    
    def update_design(self, design_id: str, updates: Dict) -> bool:
        """
        Update specific fields of a design
        
        Args:
            design_id: Design identifier
            updates: Dictionary of fields to update
            
        Returns:
            bool: True if updated successfully
        """
        try:
            # Add update timestamp
            updates['updated_at'] = datetime.utcnow().isoformat()
            
            if self.is_firebase_available:
                # Update Firebase
                doc_ref = self.db.collection(self.collection_name).document(design_id)
                doc_ref.update(updates)
                
                # Update session cache
                if design_id in st.session_state.designs:
                    st.session_state.designs[design_id].update(updates)
                
                return True
            else:
                # Update session state
                if design_id in st.session_state.designs:
                    st.session_state.designs[design_id].update(updates)
                    return True
                return False
                
        except Exception as e:
            st.error(f"Error updating design: {str(e)}")
            return False
    
    def delete_design(self, design_id: str) -> bool:
        """
        Delete a design
        
        Args:
            design_id: Design identifier
            
        Returns:
            bool: True if deleted successfully
        """
        try:
            if self.is_firebase_available:
                # Delete from Firebase
                self.db.collection(self.collection_name).document(design_id).delete()
                
                # Remove from session cache
                if design_id in st.session_state.designs:
                    del st.session_state.designs[design_id]
                
                return True
            else:
                # Delete from session state
                if design_id in st.session_state.designs:
                    del st.session_state.designs[design_id]
                    return True
                return False
                
        except Exception as e:
            st.error(f"Error deleting design: {str(e)}")
            return False
    
    def search_designs(self, search_term: str, field: str = 'name') -> List[Dict]:
        """
        Search designs by field
        
        Args:
            search_term: Text to search for
            field: Field to search in (default: 'name')
            
        Returns:
            List of matching designs
        """
        try:
            # For now, load all and filter (Firestore full-text search is limited)
            all_designs = self.list_designs(limit=1000)
            
            search_lower = search_term.lower()
            matching = []
            
            for design in all_designs:
                field_value = str(design.get(field, '')).lower()
                if search_lower in field_value:
                    matching.append(design)
            
            return matching
            
        except Exception as e:
            st.error(f"Error searching designs: {str(e)}")
            return []
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get design statistics
        
        Returns:
            Dictionary with counts by status
        """
        try:
            all_designs = self.list_designs(limit=1000)
            
            stats = {
                'total': len(all_designs),
                'draft': 0,
                'waf_review': 0,
                'stakeholder_review': 0,
                'pending_approval': 0,
                'approved': 0,
                'cost_analysis': 0,
                'deployed': 0
            }
            
            for design in all_designs:
                status = design.get('status', 'draft').lower()
                if status in stats:
                    stats[status] += 1
            
            return stats
            
        except Exception as e:
            st.error(f"Error getting stats: {str(e)}")
            return {'total': 0}

# ============================================================================
# SINGLETON INSTANCE
# ============================================================================

@st.cache_resource
def get_storage_adapter(use_firebase: bool = True) -> DesignStorageAdapter:
    """
    Get cached storage adapter instance
    
    Args:
        use_firebase: Try to use Firebase if available
        
    Returns:
        DesignStorageAdapter instance
    """
    return DesignStorageAdapter(use_firebase=use_firebase)

# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def save_design(design_id: str, design_data: Dict) -> bool:
    """Save design using default adapter"""
    adapter = get_storage_adapter()
    return adapter.save_design(design_id, design_data)

def get_design(design_id: str) -> Optional[Dict]:
    """Get design using default adapter"""
    adapter = get_storage_adapter()
    return adapter.get_design(design_id)

def list_designs(**kwargs) -> List[Dict]:
    """List designs using default adapter"""
    adapter = get_storage_adapter()
    return adapter.list_designs(**kwargs)

def update_design(design_id: str, updates: Dict) -> bool:
    """Update design using default adapter"""
    adapter = get_storage_adapter()
    return adapter.update_design(design_id, updates)

def delete_design(design_id: str) -> bool:
    """Delete design using default adapter"""
    adapter = get_storage_adapter()
    return adapter.delete_design(design_id)

# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'DesignStorageAdapter',
    'get_storage_adapter',
    'save_design',
    'get_design',
    'list_designs',
    'update_design',
    'delete_design'
]
