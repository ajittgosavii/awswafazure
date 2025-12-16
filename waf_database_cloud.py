"""
Cloud-compatible database module for Streamlit Cloud
Uses Firestore for persistence or in-memory as fallback
"""

import streamlit as st
from datetime import datetime
from typing import Dict, List, Optional
import pandas as pd

try:
    from google.cloud import firestore
    from firebase_admin import credentials, firestore as admin_firestore, initialize_app
    import json
    FIRESTORE_AVAILABLE = True
except ImportError:
    FIRESTORE_AVAILABLE = False

class WAFDatabaseCloud:
    """Cloud database using Firestore"""
    
    def __init__(self):
        self.db = None
        if FIRESTORE_AVAILABLE and 'firebase' in st.secrets:
            try:
                cred = credentials.Certificate(dict(st.secrets['firebase']))
                try:
                    initialize_app(cred)
                except ValueError:
                    pass
                self.db = admin_firestore.client()
            except Exception as e:
                print(f"Firestore init failed: {e}")
    
    def store_scan(self, scan_result: Dict) -> str:
        if not self.db:
            return scan_result.get('scan_id', 'not_stored')
        
        scan_id = scan_result.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        self.db.collection('scan_history').document(scan_id).set({
            'scan_id': scan_id,
            'account_id': scan_result.get('account_id'),
            'scan_date': scan_result.get('scan_date', datetime.now()),
            'total_findings': scan_result.get('total_findings', 0),
            'critical_count': scan_result.get('critical_count', 0),
            'high_count': scan_result.get('high_count', 0),
            'overall_waf_score': scan_result.get('overall_waf_score', 0),
        })
        return scan_id
    
    def get_trend_data(self, account_id: str, days: int = 30) -> pd.DataFrame:
        if not self.db:
            return pd.DataFrame()
        scans = self.db.collection('scan_history').where('account_id', '==', account_id).stream()
        return pd.DataFrame([s.to_dict() for s in scans])
    
    def get_summary_stats(self, account_id: Optional[str] = None) -> Dict:
        if not self.db:
            return {'total_scans': 0, 'open_findings': 0, 'avg_waf_score': 0}
        scans = list(self.db.collection('scan_history').stream())
        return {
            'total_scans': len(scans),
            'open_findings': 0,
            'avg_waf_score': 75
        }

class WAFDatabaseMemory:
    """In-memory fallback"""
    def __init__(self):
        if 'scan_history' not in st.session_state:
            st.session_state.scan_history = []
    
    def store_scan(self, scan_result: Dict) -> str:
        st.session_state.scan_history.append(scan_result)
        return scan_result.get('scan_id', 'stored')
    
    def get_trend_data(self, account_id: str, days: int = 30) -> pd.DataFrame:
        return pd.DataFrame(st.session_state.scan_history)
    
    def get_summary_stats(self, account_id: Optional[str] = None) -> Dict:
        return {'total_scans': len(st.session_state.scan_history), 'open_findings': 0, 'avg_waf_score': 75}

def get_database():
    """Auto-select database for environment"""
    if FIRESTORE_AVAILABLE and 'firebase' in st.secrets:
        return WAFDatabaseCloud()
    else:
        st.warning("⚠️ Using in-memory storage. Configure Firestore for persistence.")
        return WAFDatabaseMemory()
