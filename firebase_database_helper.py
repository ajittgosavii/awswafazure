"""
Firebase Database Helper Module
Handles persistent storage of WAF assessments in Firebase Firestore

Features:
- Save/Load WAF assessments
- Auto-sync on responses
- User-specific data isolation
- Assessment versioning
"""

import streamlit as st
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import json

def save_assessment_to_firebase(assessment_id: str, assessment_data: Dict) -> Tuple[bool, str]:
    """
    Save assessment to Firebase Firestore
    
    Args:
        assessment_id: Unique assessment identifier
        assessment_data: Assessment data dictionary
        
    Returns:
        (success, message)
    """
    try:
        # Check if Firebase is initialized
        if not st.session_state.get('firebase_initialized', False):
            return False, "Firebase not initialized"
        
        # Import Firebase components
        from firebase_auth_module import firebase_manager
        
        if firebase_manager.db is None:
            return False, "Firebase database not available"
        
        # Get current user
        user_email = st.session_state.get('user_email', 'anonymous')
        user_uid = st.session_state.get('user_uid', 'anonymous')
        
        # Prepare assessment document - PRESERVE ALL FIELDS
        assessment_doc = {
            'assessment_id': assessment_id,
            'user_email': user_email,
            'user_uid': user_uid,
            'created_at': assessment_data.get('created_at', datetime.now().isoformat()),
            'updated_at': datetime.now().isoformat(),
            
            # Assessment details
            'name': assessment_data.get('name', ''),
            'workload_name': assessment_data.get('workload_name', ''),
            'organization': assessment_data.get('organization', ''),
            'environment': assessment_data.get('environment', ''),
            'type': assessment_data.get('type', ''),
            'industry': assessment_data.get('industry', ''),
            'aws_account': assessment_data.get('aws_account', ''),
            
            # Assessment data
            'responses': assessment_data.get('responses', {}),
            'progress': assessment_data.get('progress', 0),
            'scores': assessment_data.get('scores', {}),
            'pillar_scores': assessment_data.get('pillar_scores', {}),
            'overall_score': assessment_data.get('overall_score', 0),
            'status': assessment_data.get('status', 'in_progress'),
            'action_items': assessment_data.get('action_items', []),
            
            # Scanning features
            'enable_scanning': assessment_data.get('enable_scanning', False),
            'enable_ai': assessment_data.get('enable_ai', False),
            'scan_results': assessment_data.get('scan_results'),
            'auto_detected': assessment_data.get('auto_detected', {}),
            
            # Metadata
            'metadata': {
                'version': assessment_data.get('version', '1.0'),
                'total_questions': assessment_data.get('questions_total', 205),
                'answered_questions': len(assessment_data.get('responses', {})),
                'ai_assistance_used': assessment_data.get('ai_assistance_used', 0),
                'auto_detected_count': sum(1 for r in assessment_data.get('responses', {}).values() 
                                          if r.get('auto_detected', False))
            }
        }
        
        # Save to Firestore
        firebase_manager.db.collection('waf_assessments').document(assessment_id).set(
            assessment_doc,
            merge=True  # Merge with existing document if it exists
        )
        
        return True, "Assessment saved to Firebase successfully"
        
    except Exception as e:
        return False, f"Error saving to Firebase: {str(e)}"

def load_assessment_from_firebase(assessment_id: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    Load assessment from Firebase Firestore
    
    Args:
        assessment_id: Unique assessment identifier
        
    Returns:
        (success, message, assessment_data)
    """
    try:
        # Check if Firebase is initialized
        if not st.session_state.get('firebase_initialized', False):
            return False, "Firebase not initialized", None
        
        # Import Firebase components
        from firebase_auth_module import firebase_manager
        
        if firebase_manager.db is None:
            return False, "Firebase database not available", None
        
        # Get current user
        user_uid = st.session_state.get('user_uid', 'anonymous')
        
        # Load from Firestore
        doc_ref = firebase_manager.db.collection('waf_assessments').document(assessment_id)
        doc = doc_ref.get()
        
        if not doc.exists:
            return False, "Assessment not found", None
        
        assessment_doc = doc.to_dict()
        
        # Verify user has access (owner or admin)
        if assessment_doc.get('user_uid') != user_uid:
            user_role = st.session_state.get('user_role', 'viewer')
            if user_role != 'admin':
                return False, "Access denied", None
        
        return True, "Assessment loaded successfully", assessment_doc
        
    except Exception as e:
        return False, f"Error loading from Firebase: {str(e)}", None

def list_user_assessments() -> Tuple[bool, str, List[Dict]]:
    """
    List all assessments for current user
    
    Returns:
        (success, message, list_of_assessments)
    """
    try:
        # Check if Firebase is initialized
        if not st.session_state.get('firebase_initialized', False):
            return False, "Firebase not initialized", []
        
        # Import Firebase components
        from firebase_auth_module import firebase_manager
        
        if firebase_manager.db is None:
            return False, "Firebase database not available", []
        
        # Get current user
        user_uid = st.session_state.get('user_uid', 'anonymous')
        user_role = st.session_state.get('user_role', 'viewer')
        
        # Query assessments
        if user_role == 'admin':
            # Admins can see all assessments
            docs = firebase_manager.db.collection('waf_assessments').order_by(
                'updated_at', direction='DESCENDING'
            ).stream()
        else:
            # Regular users see only their assessments
            docs = firebase_manager.db.collection('waf_assessments').where(
                'user_uid', '==', user_uid
            ).order_by('updated_at', direction='DESCENDING').stream()
        
        assessments = []
        for doc in docs:
            assessment = doc.to_dict()
            assessment['id'] = doc.id
            assessments.append(assessment)
        
        return True, f"Found {len(assessments)} assessments", assessments
        
    except Exception as e:
        return False, f"Error listing assessments: {str(e)}", []

def delete_assessment_from_firebase(assessment_id: str) -> Tuple[bool, str]:
    """
    Delete assessment from Firebase Firestore
    
    Args:
        assessment_id: Unique assessment identifier
        
    Returns:
        (success, message)
    """
    try:
        # Check if Firebase is initialized
        if not st.session_state.get('firebase_initialized', False):
            return False, "Firebase not initialized"
        
        # Import Firebase components
        from firebase_auth_module import firebase_manager
        
        if firebase_manager.db is None:
            return False, "Firebase database not available"
        
        # Get current user
        user_uid = st.session_state.get('user_uid', 'anonymous')
        user_role = st.session_state.get('user_role', 'viewer')
        
        # Check permissions
        doc_ref = firebase_manager.db.collection('waf_assessments').document(assessment_id)
        doc = doc_ref.get()
        
        if doc.exists:
            assessment_doc = doc.to_dict()
            if assessment_doc.get('user_uid') != user_uid and user_role != 'admin':
                return False, "Access denied"
        
        # Delete
        doc_ref.delete()
        
        return True, "Assessment deleted successfully"
        
    except Exception as e:
        return False, f"Error deleting assessment: {str(e)}"

def auto_sync_response(assessment_id: str, question_id: str, response_data: Dict) -> bool:
    """
    Auto-sync individual response to Firebase (lightweight update)
    
    Args:
        assessment_id: Assessment identifier
        question_id: Question identifier
        response_data: Response data
        
    Returns:
        success: bool
    """
    try:
        if not st.session_state.get('firebase_initialized', False):
            return False
        
        from firebase_auth_module import firebase_manager
        
        if firebase_manager.db is None:
            return False
        
        # Update just the response field
        doc_ref = firebase_manager.db.collection('waf_assessments').document(assessment_id)
        doc_ref.update({
            f'responses.{question_id}': response_data,
            'updated_at': datetime.now().isoformat()
        })
        
        return True
        
    except Exception as e:
        st.error(f"Auto-sync failed: {str(e)}")
        return False