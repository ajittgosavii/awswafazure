"""
Enterprise WAF Database using existing Firestore connection
Extends your current Firebase setup for historical tracking
"""

import streamlit as st
from datetime import datetime
from typing import Dict, List, Optional
import pandas as pd

class WAFDatabaseFirestore:
    """Uses your existing Firestore for WAF scan storage"""
    
    def __init__(self):
        """Initialize using existing Firebase connection"""
        self.db = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Attempt to connect to existing Firestore"""
        try:
            # Method 1: Check if Firebase is already initialized via firebase_auth_module
            if st.session_state.get('firebase_initialized', False):
                from firebase_auth_module import firebase_manager
                if firebase_manager and firebase_manager.db:
                    self.db = firebase_manager.db
                    print("✅ Connected to existing Firestore via firebase_manager")
                    return
            
            # Method 2: Try to initialize Firebase from Streamlit secrets
            if 'firebase' in st.secrets:
                try:
                    import firebase_admin
                    from firebase_admin import credentials, firestore
                    
                    # Check if Firebase is already initialized
                    if not firebase_admin._apps:
                        cred = credentials.Certificate(dict(st.secrets['firebase']))
                        firebase_admin.initialize_app(cred)
                    
                    self.db = firestore.client()
                    print("✅ Connected to Firestore from secrets")
                    return
                    
                except Exception as e:
                    print(f"⚠️ Firestore initialization from secrets failed: {e}")
            
            print("⚠️ Firestore not available. Historical tracking disabled.")
            
        except Exception as e:
            print(f"⚠️ Firestore connection failed: {e}")
            self.db = None
    
    def is_connected(self) -> bool:
        """Check if database is connected"""
        return self.db is not None
    
    def store_scan(self, scan_result: Dict) -> str:
        """Store WAF scan in Firestore"""
        
        if not self.db:
            print("⚠️ Firestore not available")
            return 'not_stored'
        
        try:
            scan_id = scan_result.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
            user_email = st.session_state.get('user_email', 'system')
            user_uid = st.session_state.get('user_uid', 'system')
            
            # Store scan summary
            scan_doc = {
                'scan_id': scan_id,
                'account_id': scan_result.get('account_id'),
                'account_name': scan_result.get('account_name'),
                'scan_date': scan_result.get('scan_date', datetime.now()),
                'user_email': user_email,
                'user_uid': user_uid,
                'total_findings': scan_result.get('total_findings', 0),
                'critical_count': scan_result.get('critical_count', 0),
                'high_count': scan_result.get('high_count', 0),
                'medium_count': scan_result.get('medium_count', 0),
                'low_count': scan_result.get('low_count', 0),
                'overall_waf_score': scan_result.get('overall_waf_score', 0),
                'pillar_scores': scan_result.get('pillar_scores', {}),
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            self.db.collection('waf_scans').document(scan_id).set(scan_doc)
            
            # Store findings
            findings_count = 0
            for finding in scan_result.get('findings', []):
                finding_id = finding.get('finding_id', f"{scan_id}_{finding.get('title', 'unknown')}")
                
                finding_doc = {
                    'scan_id': scan_id,
                    'account_id': scan_result.get('account_id'),
                    'finding_id': finding_id,
                    'severity': finding.get('severity', 'MEDIUM'),
                    'title': finding.get('title', ''),
                    'description': finding.get('description', ''),
                    'service': finding.get('service', ''),
                    'pillar': finding.get('pillar', ''),
                    'status': 'open',
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'user_email': user_email,
                    'created_at': datetime.now()
                }
                
                # Check if finding already exists
                existing = self.db.collection('waf_findings').document(finding_id).get()
                if existing.exists:
                    # Update last_seen
                    self.db.collection('waf_findings').document(finding_id).update({
                        'last_seen': datetime.now(),
                        'updated_at': datetime.now()
                    })
                else:
                    # Create new finding
                    self.db.collection('waf_findings').document(finding_id).set(finding_doc)
                
                findings_count += 1
            
            print(f"✅ Scan {scan_id} stored in Firestore ({findings_count} findings)")
            return scan_id
            
        except Exception as e:
            print(f"❌ Error storing scan: {e}")
            import traceback
            traceback.print_exc()
            return 'error'
    
    def get_trend_data(self, account_id: str, days: int = 30) -> pd.DataFrame:
        """Get historical scan trends"""
        if not self.db:
            return pd.DataFrame()
        
        try:
            scans_ref = self.db.collection('waf_scans')\
                .where('account_id', '==', account_id)\
                .order_by('scan_date', direction=firestore.Query.DESCENDING)\
                .limit(100)
            
            scans = scans_ref.stream()
            data = []
            for scan in scans:
                scan_dict = scan.to_dict()
                # Convert Firestore timestamp to string
                if 'scan_date' in scan_dict and hasattr(scan_dict['scan_date'], 'strftime'):
                    scan_dict['scan_date'] = scan_dict['scan_date'].strftime('%Y-%m-%d %H:%M:%S')
                elif 'scan_date' in scan_dict and isinstance(scan_dict['scan_date'], str):
                    # Already a string, keep as is
                    pass
                data.append(scan_dict)
            
            return pd.DataFrame(data)
        except Exception as e:
            print(f"❌ Error getting trends: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()
    
    def get_summary_stats(self, account_id: Optional[str] = None) -> Dict:
        """Get summary statistics"""
        if not self.db:
            return {'total_scans': 0, 'open_findings': 0, 'resolved_findings': 0, 'avg_waf_score': 0}
        
        try:
            scans_ref = self.db.collection('waf_scans')
            if account_id:
                scans_ref = scans_ref.where('account_id', '==', account_id)
            scans = list(scans_ref.stream())
            
            findings_ref = self.db.collection('waf_findings')
            if account_id:
                findings_ref = findings_ref.where('account_id', '==', account_id)
            findings = list(findings_ref.stream())
            
            open_count = sum(1 for f in findings if f.to_dict().get('status') == 'open')
            resolved_count = sum(1 for f in findings if f.to_dict().get('status') == 'resolved')
            scores = [s.to_dict().get('overall_waf_score', 0) for s in scans if s.to_dict().get('overall_waf_score')]
            avg_score = sum(scores) / len(scores) if scores else 0
            
            return {
                'total_scans': len(scans),
                'open_findings': open_count,
                'resolved_findings': resolved_count,
                'avg_waf_score': avg_score
            }
        except Exception as e:
            print(f"❌ Error getting stats: {e}")
            return {'total_scans': 0, 'open_findings': 0, 'resolved_findings': 0, 'avg_waf_score': 0}
    
    def assign_finding(self, finding_id: str, assignee_email: str, due_date: Optional[datetime] = None, 
                      priority: str = 'normal', notes: str = '') -> bool:
        """Assign finding to team member"""
        if not self.db:
            return False
        
        try:
            assignment = {
                'finding_id': finding_id,
                'assignee_email': assignee_email,
                'assigned_by': st.session_state.get('user_email', 'system'),
                'assigned_date': datetime.now(),
                'due_date': due_date,
                'priority': priority,
                'notes': notes,
                'status': 'assigned'
            }
            self.db.collection('waf_assignments').document(f"{finding_id}_{assignee_email}").set(assignment)
            self.db.collection('waf_findings').document(finding_id).update({
                'status': 'assigned',
                'assigned_to': assignee_email,
                'updated_at': datetime.now()
            })
            return True
        except Exception as e:
            print(f"❌ Error assigning finding: {e}")
            return False
    
    def add_comment(self, finding_id: str, author: str, comment_text: str) -> bool:
        """Add comment to finding"""
        if not self.db:
            return False
        
        try:
            comment = {
                'finding_id': finding_id,
                'author': author,
                'comment_text': comment_text,
                'created_at': datetime.now()
            }
            self.db.collection('waf_comments').add(comment)
            return True
        except Exception as e:
            print(f"❌ Error adding comment: {e}")
            return False
    
    def get_comments(self, finding_id: str) -> List[Dict]:
        """Get all comments for a finding"""
        if not self.db:
            return []
        
        try:
            comments_ref = self.db.collection('waf_comments')\
                .where('finding_id', '==', finding_id)\
                .order_by('created_at', direction=firestore.Query.DESCENDING)
            
            comments = []
            for comment in comments_ref.stream():
                comments.append(comment.to_dict())
            return comments
        except Exception as e:
            print(f"❌ Error getting comments: {e}")
            return []
    
    def get_assigned_findings(self, user_email: str) -> List[Dict]:
        """Get findings assigned to user"""
        if not self.db:
            return []
        
        try:
            findings_ref = self.db.collection('waf_findings')\
                .where('assigned_to', '==', user_email)\
                .where('status', 'in', ['assigned', 'in_progress'])
            
            findings = []
            for finding in findings_ref.stream():
                findings.append(finding.to_dict())
            return findings
        except Exception as e:
            print(f"❌ Error getting assigned findings: {e}")
            return []


def get_database():
    """Get WAF database using existing Firestore"""
    return WAFDatabaseFirestore()
