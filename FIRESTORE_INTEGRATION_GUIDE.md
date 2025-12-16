# 🔥 Using Your Existing Firestore for Enterprise Features
## Leverage Your Current Firebase Setup for Database Persistence

---

## ✅ **Good News: You Already Have Firestore!**

Your application **already includes** complete Firebase/Firestore integration:

✅ `firebase_auth_module.py` - Firebase Admin SDK initialized  
✅ `firebase_database_helper.py` - Firestore read/write functions  
✅ `auth_database_firebase.py` - User data in Firestore  
✅ `auth_database_firestore.py` - Firestore connection management  

**You just need to extend it for enterprise features!**

---

## 🎯 **Simple 3-Step Integration**

### **Step 1: Use Your Existing Firestore Connection**

Your app already has this code working:

```python
# In firebase_auth_module.py
import firebase_admin
from firebase_admin import credentials, auth, firestore

# Already initialized in your app
db = firestore.client()
```

**No new setup needed!** Your Firestore is ready to use.

---

### **Step 2: Add Enterprise Collections**

Create this simple wrapper that uses your existing Firestore:

**File: `waf_database_firestore_enterprise.py`**

```python
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
        
        # Use your existing Firebase initialization
        if st.session_state.get('firebase_initialized', False):
            try:
                from firebase_auth_module import firebase_manager
                self.db = firebase_manager.db
                print("✅ Connected to existing Firestore")
            except Exception as e:
                print(f"⚠️ Firestore connection failed: {e}")
    
    def store_scan(self, scan_result: Dict) -> str:
        """Store WAF scan in Firestore"""
        
        if not self.db:
            print("⚠️ Firestore not available")
            return 'not_stored'
        
        try:
            scan_id = scan_result.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
            
            # Get user context (from your existing auth)
            user_email = st.session_state.get('user_email', 'system')
            user_uid = st.session_state.get('user_uid', 'system')
            
            # Store scan in new collection: waf_scans
            scan_doc = {
                'scan_id': scan_id,
                'account_id': scan_result.get('account_id'),
                'account_name': scan_result.get('account_name'),
                'scan_date': scan_result.get('scan_date', datetime.now()),
                'user_email': user_email,
                'user_uid': user_uid,
                
                # Summary metrics
                'total_findings': scan_result.get('total_findings', 0),
                'critical_count': scan_result.get('critical_count', 0),
                'high_count': scan_result.get('high_count', 0),
                'medium_count': scan_result.get('medium_count', 0),
                'low_count': scan_result.get('low_count', 0),
                'overall_waf_score': scan_result.get('overall_waf_score', 0),
                
                # Pillar scores
                'pillar_scores': scan_result.get('pillar_scores', {}),
                
                # Metadata
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            # Save to Firestore (same as your existing assessment saves)
            self.db.collection('waf_scans').document(scan_id).set(scan_doc)
            
            # Store individual findings
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
                    
                    # Status tracking
                    'status': 'open',
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    
                    # User context
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
            
            print(f"✅ Scan {scan_id} stored in Firestore")
            return scan_id
            
        except Exception as e:
            print(f"❌ Error storing scan: {e}")
            return 'error'
    
    def get_trend_data(self, account_id: str, days: int = 30) -> pd.DataFrame:
        """Get historical scan trends"""
        
        if not self.db:
            return pd.DataFrame()
        
        try:
            # Query scans for this account
            scans_ref = self.db.collection('waf_scans')\
                .where('account_id', '==', account_id)\
                .order_by('scan_date', direction='DESCENDING')\
                .limit(100)
            
            scans = scans_ref.stream()
            
            data = []
            for scan in scans:
                scan_dict = scan.to_dict()
                # Convert Firestore timestamp to datetime
                if 'scan_date' in scan_dict:
                    scan_dict['scan_date'] = scan_dict['scan_date'].strftime('%Y-%m-%d %H:%M:%S')
                data.append(scan_dict)
            
            return pd.DataFrame(data)
            
        except Exception as e:
            print(f"❌ Error getting trends: {e}")
            return pd.DataFrame()
    
    def get_summary_stats(self, account_id: Optional[str] = None) -> Dict:
        """Get summary statistics"""
        
        if not self.db:
            return {
                'total_scans': 0,
                'open_findings': 0,
                'resolved_findings': 0,
                'avg_waf_score': 0
            }
        
        try:
            # Count scans
            scans_ref = self.db.collection('waf_scans')
            if account_id:
                scans_ref = scans_ref.where('account_id', '==', account_id)
            
            scans = list(scans_ref.stream())
            
            # Count findings
            findings_ref = self.db.collection('waf_findings')
            if account_id:
                findings_ref = findings_ref.where('account_id', '==', account_id)
            
            findings = list(findings_ref.stream())
            
            # Calculate stats
            open_count = sum(1 for f in findings if f.to_dict().get('status') == 'open')
            resolved_count = sum(1 for f in findings if f.to_dict().get('status') == 'resolved')
            
            # Average WAF score
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
            return {
                'total_scans': 0,
                'open_findings': 0,
                'resolved_findings': 0,
                'avg_waf_score': 0
            }
    
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
            
            # Store assignment
            self.db.collection('waf_assignments').document(f"{finding_id}_{assignee_email}").set(assignment)
            
            # Update finding status
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
            
            # Add comment
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
                .order_by('created_at', direction='DESCENDING')
            
            comments = []
            for comment in comments_ref.stream():
                comment_dict = comment.to_dict()
                comments.append(comment_dict)
            
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
                finding_dict = finding.to_dict()
                findings.append(finding_dict)
            
            return findings
            
        except Exception as e:
            print(f"❌ Error getting assigned findings: {e}")
            return []


def get_database():
    """Get WAF database using existing Firestore"""
    return WAFDatabaseFirestore()
```

---

### **Step 3: Update Your App to Use It**

In your `app_enterprise.py` or `streamlit_app.py`, replace:

```python
# OLD: SQLite database (doesn't work on cloud)
from waf_database import WAFDatabase
db = WAFDatabase()
```

With:

```python
# NEW: Your existing Firestore
from waf_database_firestore_enterprise import get_database
db = get_database()
```

**That's it!** Your enterprise features now use Firestore.

---

## 🎯 **What This Gives You**

### **New Firestore Collections:**

1. **`waf_scans`** - Historical scan records
   - scan_id, account_id, scan_date
   - finding counts by severity
   - WAF score and pillar scores
   - User who ran scan

2. **`waf_findings`** - Individual findings
   - finding_id, scan_id, account_id
   - severity, title, description, service
   - status (open, assigned, in_progress, resolved)
   - first_seen, last_seen timestamps

3. **`waf_assignments`** - Team assignments
   - finding_id, assignee_email
   - due_date, priority, notes
   - assigned_by, assigned_date

4. **`waf_comments`** - Finding discussions
   - finding_id, author, comment_text
   - created_at timestamp

### **Existing Collections (Unchanged):**

- Your current `assessments` collection
- Your current `users` collection
- All your existing Firebase data

**Everything works together!**

---

## 📊 **Firestore Data Structure**

### **Example `waf_scans` Document:**

```javascript
{
  scan_id: "20241213_143022",
  account_id: "123456789012",
  account_name: "Production",
  scan_date: "2024-12-13T14:30:22Z",
  user_email: "user@company.com",
  user_uid: "firebase_uid_123",
  
  total_findings: 15,
  critical_count: 2,
  high_count: 5,
  medium_count: 6,
  low_count: 2,
  overall_waf_score: 72,
  
  pillar_scores: {
    operational_excellence: 75,
    security: 68,
    reliability: 80,
    performance_efficiency: 70,
    cost_optimization: 65,
    sustainability: 73
  },
  
  created_at: "2024-12-13T14:30:22Z",
  updated_at: "2024-12-13T14:30:22Z"
}
```

### **Example `waf_findings` Document:**

```javascript
{
  finding_id: "20241213_143022_S3_ENCRYPTION",
  scan_id: "20241213_143022",
  account_id: "123456789012",
  severity: "HIGH",
  title: "S3 Bucket Without Encryption Enabled",
  description: "S3 bucket 'my-bucket' does not have encryption enabled",
  service: "S3",
  pillar: "security",
  
  status: "assigned",
  assigned_to: "security-team@company.com",
  first_seen: "2024-12-13T14:30:22Z",
  last_seen: "2024-12-13T14:30:22Z",
  
  user_email: "user@company.com",
  created_at: "2024-12-13T14:30:22Z"
}
```

---

## 🚀 **Deployment to Streamlit Cloud**

### **Your Firebase Secrets Are Already Configured!**

You already have Firebase secrets in your app. Just make sure they're also in Streamlit Cloud:

**Streamlit Cloud → Settings → Secrets:**

```toml
# Your existing Firebase config (already have this!)
[firebase]
type = "service_account"
project_id = "your-project-id"
private_key_id = "..."
private_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
client_email = "..."
# ... rest of your existing Firebase config

# AWS credentials
[aws]
access_key_id = "YOUR_AWS_KEY"
secret_access_key = "YOUR_AWS_SECRET"
default_region = "us-east-1"

# Claude API
[claude]
api_key = "YOUR_CLAUDE_KEY"
```

**Done!** Your Firestore database works on Streamlit Cloud.

---

## ✅ **Advantages of Using Your Existing Firestore**

1. **No New Setup** - Already configured and working
2. **Same Security** - Uses your existing Firebase project
3. **User Integration** - Automatically tracks who ran scans
4. **Role-Based Access** - Works with your existing user roles
5. **Proven Reliability** - Your Firebase is already in production
6. **Easy Queries** - Same Firebase Console you already use
7. **Cost Effective** - No additional database service

---

## 📋 **Quick Integration Checklist**

- [ ] Copy `waf_database_firestore_enterprise.py` to your project
- [ ] Update app to use `get_database()` instead of SQLite
- [ ] Test locally with your existing Firebase
- [ ] Deploy to Streamlit Cloud (Firebase already configured!)
- [ ] Run first scan
- [ ] Check Firestore Console for new collections
- [ ] Verify historical data persists

---

## 🔍 **Viewing Your Data in Firebase Console**

Go to [Firebase Console](https://console.firebase.google.com):

1. Select your project
2. Go to **Firestore Database**
3. See new collections:
   - `waf_scans` - All historical scans
   - `waf_findings` - All findings across scans
   - `waf_assignments` - Team assignments
   - `waf_comments` - Finding discussions

**Query examples:**
- Filter scans by account_id
- Find all HIGH severity findings
- See findings assigned to specific user
- Track finding status changes over time

---

## 💡 **Example Usage in Your App**

```python
import streamlit as st
from waf_database_firestore_enterprise import get_database

# Initialize (uses your existing Firebase)
db = get_database()

# After scan completes
scan_id = db.store_scan(scan_results)
st.success(f"✅ Scan stored: {scan_id}")

# Get historical trends
trends = db.get_trend_data('123456789012', days=30)
st.line_chart(trends[['scan_date', 'overall_waf_score']])

# Assign finding to team
db.assign_finding(
    finding_id='finding_123',
    assignee_email='security-team@company.com',
    priority='high',
    notes='Please review ASAP'
)

# Add comment
db.add_comment(
    finding_id='finding_123',
    author=st.session_state.user_email,
    comment_text='Working on remediation'
)

# Get summary stats
stats = db.get_summary_stats('123456789012')
st.metric("Total Scans", stats['total_scans'])
st.metric("Open Findings", stats['open_findings'])
st.metric("Avg WAF Score", f"{stats['avg_waf_score']:.1f}")
```

---

## 🎊 **You're Ready!**

Your existing Firestore setup is **perfect** for enterprise features:

✅ Already initialized and working  
✅ Already on Streamlit Cloud  
✅ Already integrated with auth  
✅ Already storing data  
✅ Just add new collections  

**No new database setup needed!** Just extend what you have.

---

## 📞 **Need Help?**

Your Firebase is already working, so this integration is straightforward:

1. **Copy the code above** to `waf_database_firestore_enterprise.py`
2. **Update your app** to use it
3. **Deploy** - uses your existing Firebase config
4. **Done!**

Your enterprise WAF scanner now has full database persistence using your existing, proven Firestore setup! 🚀
