# ☁️ Streamlit Cloud Deployment Guide - AWS WAF Scanner Enterprise Edition

## 🎯 **Deploying to Streamlit Cloud**

This guide shows you how to deploy your AWS WAF Scanner Enterprise Edition to Streamlit Cloud.

---

## ⚠️ **Important Cloud Considerations**

### **1. Database Persistence**

❌ **SQLite doesn't persist on Streamlit Cloud** (storage resets on restart)

✅ **Solutions:**
- **Option A:** Use external database (PostgreSQL, MySQL)
- **Option B:** Use cloud storage (AWS S3, Google Cloud Storage)
- **Option C:** Use Firestore (already in your app!)
- **Option D:** Accept ephemeral storage (database recreates on restart)

**Recommendation:** Use **Firestore** (you already have auth modules for it!)

### **2. File System is Read-Only**

- Cannot write to local filesystem except `/tmp`
- PDF reports need to be generated in memory
- Downloads work fine

### **3. Secrets Management**

- Use Streamlit Cloud secrets (not environment variables)
- Configure in Streamlit Cloud dashboard

---

## 🚀 **Deployment Steps**

### **Step 1: Prepare GitHub Repository**

```bash
# 1. Extract your enterprise package
unzip aws-waf-scanner-enterprise-v4.0.zip

# 2. Initialize git repository
cd aws-waf-scanner-enterprise
git init
git add .
git commit -m "Initial commit: AWS WAF Scanner Enterprise v4.0"

# 3. Create GitHub repository (on github.com)
# Name: aws-waf-scanner-enterprise

# 4. Push to GitHub
git remote add origin https://github.com/YOUR_USERNAME/aws-waf-scanner-enterprise.git
git branch -M main
git push -u origin main
```

---

### **Step 2: Configure for Streamlit Cloud**

#### **A. Update requirements.txt for Cloud**

Your `requirements.txt` is already perfect! But ensure these are included:

```txt
streamlit>=1.28.0
boto3>=1.34.0
pandas>=2.0.0
plotly>=5.17.0
click>=8.1.0
anthropic>=0.18.0
python-docx>=0.8.11
reportlab>=4.0.0
Pillow>=10.0.0
pyyaml>=6.0

# For cloud database (optional)
google-cloud-firestore>=2.11.0
firebase-admin>=6.2.0
```

#### **B. Create `.streamlit/config.toml`**

Create this file in your repo:

```bash
mkdir -p .streamlit
cat > .streamlit/config.toml << 'EOF'
[theme]
primaryColor = "#FF9900"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#262730"
font = "sans serif"

[server]
maxUploadSize = 200
enableXsrfProtection = true
enableCORS = false
headless = true

[browser]
gatherUsageStats = false
EOF
```

#### **C. Create Cloud-Compatible Database Module**

Create `waf_database_cloud.py`:

```python
"""
Cloud-compatible database module
Uses Firestore for persistence on Streamlit Cloud
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
    print("⚠️ Firestore not available. Install google-cloud-firestore for persistence.")


class WAFDatabaseCloud:
    """Cloud-compatible database using Firestore"""
    
    def __init__(self):
        self.db = None
        
        if FIRESTORE_AVAILABLE:
            try:
                # Initialize Firestore from Streamlit secrets
                if 'firebase' in st.secrets:
                    # Use service account from secrets
                    cred = credentials.Certificate(dict(st.secrets['firebase']))
                    
                    # Check if already initialized
                    try:
                        initialize_app(cred)
                    except ValueError:
                        pass  # Already initialized
                    
                    self.db = admin_firestore.client()
                    print("✅ Firestore connected successfully")
                else:
                    print("⚠️ Firebase secrets not configured")
            except Exception as e:
                print(f"⚠️ Firestore initialization failed: {e}")
    
    def store_scan(self, scan_result: Dict) -> str:
        """Store scan in Firestore"""
        
        if not self.db:
            print("⚠️ No database connection. Scan not stored.")
            return scan_result.get('scan_id', 'not_stored')
        
        try:
            scan_id = scan_result.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
            
            # Store in Firestore
            doc_ref = self.db.collection('scan_history').document(scan_id)
            doc_ref.set({
                'scan_id': scan_id,
                'account_id': scan_result.get('account_id'),
                'account_name': scan_result.get('account_name'),
                'scan_date': scan_result.get('scan_date', datetime.now()),
                'total_findings': scan_result.get('total_findings', 0),
                'critical_count': scan_result.get('critical_count', 0),
                'high_count': scan_result.get('high_count', 0),
                'medium_count': scan_result.get('medium_count', 0),
                'low_count': scan_result.get('low_count', 0),
                'overall_waf_score': scan_result.get('overall_waf_score', 0),
                'timestamp': firestore.SERVER_TIMESTAMP
            })
            
            # Store findings
            for finding in scan_result.get('findings', []):
                finding_id = finding.get('id', finding.get('finding_id'))
                self.db.collection('findings').document(finding_id).set({
                    'scan_id': scan_id,
                    'account_id': scan_result.get('account_id'),
                    'finding_id': finding_id,
                    'severity': finding.get('severity'),
                    'title': finding.get('title'),
                    'service': finding.get('service'),
                    'status': 'open',
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now()
                })
            
            return scan_id
            
        except Exception as e:
            print(f"❌ Error storing scan: {e}")
            return 'error'
    
    def get_trend_data(self, account_id: str, days: int = 30) -> pd.DataFrame:
        """Get trend data from Firestore"""
        
        if not self.db:
            return pd.DataFrame()
        
        try:
            # Query scans for account
            scans = self.db.collection('scan_history')\
                .where('account_id', '==', account_id)\
                .order_by('scan_date', direction=firestore.Query.DESCENDING)\
                .limit(50)\
                .stream()
            
            data = []
            for scan in scans:
                data.append(scan.to_dict())
            
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
            # Get scan count
            scans_ref = self.db.collection('scan_history')
            if account_id:
                scans_ref = scans_ref.where('account_id', '==', account_id)
            
            scans = list(scans_ref.stream())
            
            # Get findings count
            findings_ref = self.db.collection('findings')
            if account_id:
                findings_ref = findings_ref.where('account_id', '==', account_id)
            
            findings = list(findings_ref.stream())
            
            open_count = sum(1 for f in findings if f.to_dict().get('status') == 'open')
            resolved_count = sum(1 for f in findings if f.to_dict().get('status') == 'resolved')
            
            # Calculate average WAF score
            scores = [s.to_dict().get('overall_waf_score', 0) for s in scans]
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


# Fallback to in-memory storage if Firestore not available
class WAFDatabaseMemory:
    """In-memory database (for testing or when Firestore unavailable)"""
    
    def __init__(self):
        if 'scan_history' not in st.session_state:
            st.session_state.scan_history = []
        if 'findings' not in st.session_state:
            st.session_state.findings = []
    
    def store_scan(self, scan_result: Dict) -> str:
        scan_id = scan_result.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
        st.session_state.scan_history.append(scan_result)
        return scan_id
    
    def get_trend_data(self, account_id: str, days: int = 30) -> pd.DataFrame:
        scans = [s for s in st.session_state.scan_history 
                if s.get('account_id') == account_id]
        return pd.DataFrame(scans)
    
    def get_summary_stats(self, account_id: Optional[str] = None) -> Dict:
        return {
            'total_scans': len(st.session_state.scan_history),
            'open_findings': len(st.session_state.findings),
            'resolved_findings': 0,
            'avg_waf_score': 75
        }


# Auto-select appropriate database
def get_database():
    """Get appropriate database for environment"""
    
    if FIRESTORE_AVAILABLE and 'firebase' in st.secrets:
        return WAFDatabaseCloud()
    else:
        st.warning("⚠️ Using in-memory storage. Data will not persist across restarts. Configure Firestore for persistence.")
        return WAFDatabaseMemory()
```

#### **D. Update `app_enterprise.py` for Cloud**

Add this at the top of `app_enterprise.py`:

```python
# Use cloud-compatible database
try:
    from waf_database_cloud import get_database
    db = get_database()
    st.session_state.db = db
    CLOUD_MODE = True
except ImportError:
    from waf_database import WAFDatabase
    db = WAFDatabase()
    st.session_state.db = db
    CLOUD_MODE = False
```

---

### **Step 3: Configure Secrets in Streamlit Cloud**

#### **Navigate to:** Streamlit Cloud Dashboard → Your App → Settings → Secrets

Add this configuration:

```toml
# AWS Credentials
[aws]
access_key_id = "YOUR_AWS_ACCESS_KEY_ID"
secret_access_key = "YOUR_AWS_SECRET_ACCESS_KEY"
default_region = "us-east-1"

# Claude API
[claude]
api_key = "YOUR_CLAUDE_API_KEY"

# Firebase/Firestore (for database persistence)
[firebase]
type = "service_account"
project_id = "your-project-id"
private_key_id = "your-private-key-id"
private_key = "-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----\n"
client_email = "your-service-account@your-project.iam.gserviceaccount.com"
client_id = "your-client-id"
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
client_x509_cert_url = "https://www.googleapis.com/robot/v1/metadata/x509/your-service-account%40your-project.iam.gserviceaccount.com"
```

**How to get Firebase credentials:**
1. Go to Firebase Console (console.firebase.google.com)
2. Create project or use existing
3. Settings → Service Accounts
4. Generate new private key
5. Copy JSON content to secrets above

---

### **Step 4: Deploy to Streamlit Cloud**

1. **Go to:** [share.streamlit.io](https://share.streamlit.io)
2. **Click:** "New app"
3. **Select:**
   - Repository: `your-username/aws-waf-scanner-enterprise`
   - Branch: `main`
   - Main file: `app_enterprise.py` (or `streamlit_app.py`)
4. **Click:** "Deploy"

**Your app will be live at:** `https://your-app-name.streamlit.app`

---

## 🔧 **Cloud-Specific Optimizations**

### **1. Reduce Package Size**

Create `.streamlit/packages.txt` (for system dependencies):
```
# Add any system packages if needed
# Example:
# libgl1-mesa-glx
```

### **2. Optimize Requirements**

Only include what you need for cloud:
```txt
# Core (required)
streamlit>=1.28.0
boto3>=1.34.0
pandas>=2.0.0
plotly>=5.17.0
anthropic>=0.18.0

# Documents
python-docx>=0.8.11
reportlab>=4.0.0
Pillow>=10.0.0

# Cloud database
google-cloud-firestore>=2.11.0
firebase-admin>=6.2.0

# Utilities
pyyaml>=6.0
python-dateutil>=2.8.2
requests>=2.31.0

# Optional (only if using)
click>=8.1.0  # Only if using CLI locally
```

### **3. Handle PDF Generation in Cloud**

Update PDF generation to use in-memory:

```python
import io
from reportlab.pdfgen import canvas

def generate_pdf_cloud(scan_result):
    """Generate PDF in memory for cloud"""
    
    buffer = io.BytesIO()
    
    # Generate PDF to buffer
    # ... your PDF generation code ...
    
    buffer.seek(0)
    return buffer

# In your app:
pdf_buffer = generate_pdf_cloud(results)

st.download_button(
    label="📥 Download PDF Report",
    data=pdf_buffer,
    file_name=f"waf_report_{scan_id}.pdf",
    mime="application/pdf"
)
```

---

## 📁 **Recommended File Structure for Cloud**

```
aws-waf-scanner-enterprise/
├── .streamlit/
│   ├── config.toml              # Theme & config
│   └── secrets.toml             # LOCAL ONLY (in .gitignore)
│
├── app_enterprise.py            # Main entry point
├── streamlit_app.py             # Alternative entry point
│
├── waf_database_cloud.py        # ✨ NEW: Cloud database
├── waf_database.py              # Original (for local use)
├── compliance_mapper.py
├── cost_calculator.py
├── remediation_engine.py
├── interactive_dashboard.py
├── waf_cli.py
│
├── requirements.txt             # Cloud dependencies
├── .gitignore                   # Important!
└── README.md
```

### **Important `.gitignore`:**

```gitignore
# Secrets
.streamlit/secrets.toml
*.env

# Database
*.db
*.sqlite

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python

# Virtual environment
venv/
ENV/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs
*.log
```

---

## 🔐 **Security Best Practices for Cloud**

### **1. Never Commit Secrets**

❌ **Don't:**
- Put credentials in code
- Commit `.streamlit/secrets.toml`
- Hardcode API keys

✅ **Do:**
- Use Streamlit Cloud secrets
- Add secrets.toml to .gitignore
- Use environment detection

### **2. Secure AWS Access**

```python
import streamlit as st
import boto3

def get_aws_session():
    """Get AWS session from Streamlit secrets"""
    
    if 'aws' in st.secrets:
        return boto3.Session(
            aws_access_key_id=st.secrets['aws']['access_key_id'],
            aws_secret_access_key=st.secrets['aws']['secret_access_key'],
            region_name=st.secrets['aws'].get('default_region', 'us-east-1')
        )
    else:
        st.error("❌ AWS credentials not configured in Streamlit Cloud secrets")
        st.stop()
```

### **3. Rate Limiting**

Add to your app:

```python
import streamlit as st
from datetime import datetime, timedelta

def check_rate_limit(max_scans_per_hour=10):
    """Prevent abuse on cloud"""
    
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []
    
    # Remove old scans (>1 hour)
    cutoff = datetime.now() - timedelta(hours=1)
    st.session_state.scan_history = [
        s for s in st.session_state.scan_history 
        if s > cutoff
    ]
    
    # Check limit
    if len(st.session_state.scan_history) >= max_scans_per_hour:
        st.error("⚠️ Rate limit exceeded. Please wait before scanning again.")
        st.stop()
    
    # Add current scan
    st.session_state.scan_history.append(datetime.now())
```

---

## 📊 **Monitoring Your Cloud App**

### **Check App Health:**

```python
import streamlit as st
from datetime import datetime

def show_health_status():
    """Display app health in sidebar"""
    
    with st.sidebar:
        st.markdown("---")
        st.caption("🏥 App Health")
        
        # Database status
        if st.session_state.db:
            st.caption("✅ Database: Connected")
        else:
            st.caption("⚠️ Database: In-Memory")
        
        # AWS status
        try:
            session = get_aws_session()
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            st.caption(f"✅ AWS: Connected")
        except:
            st.caption("❌ AWS: Not Connected")
        
        # Deployment info
        st.caption(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        st.caption("🚀 v4.0 Enterprise")
```

---

## 🚨 **Troubleshooting Cloud Deployment**

### **Issue: App won't start**

**Check:**
1. Requirements.txt has all packages
2. No syntax errors in code
3. Secrets are configured correctly
4. Check Streamlit Cloud logs

### **Issue: Database not persisting**

**Solutions:**
1. Configure Firestore secrets
2. Use `waf_database_cloud.py`
3. Or accept ephemeral storage (warning to users)

### **Issue: AWS credentials not working**

**Check:**
1. Secrets format matches exactly
2. No extra quotes or spaces
3. Test with simple STS call:
```python
import boto3
sts = boto3.client('sts')
print(sts.get_caller_identity())
```

### **Issue: App is slow**

**Optimizations:**
1. Use `@st.cache_data` for expensive operations
2. Limit concurrent scans
3. Reduce chart complexity
4. Use pagination for large results

---

## ✅ **Cloud Deployment Checklist**

- [ ] GitHub repository created
- [ ] Code pushed to GitHub
- [ ] `.gitignore` configured (secrets excluded)
- [ ] `requirements.txt` optimized for cloud
- [ ] `waf_database_cloud.py` created
- [ ] Streamlit Cloud app created
- [ ] Secrets configured in dashboard
- [ ] Firebase/Firestore set up (optional)
- [ ] App deployed successfully
- [ ] First scan tested
- [ ] Database persistence verified
- [ ] PDF download tested
- [ ] Team members invited

---

## 🎯 **Recommended Cloud Setup**

**Best Practice:**

1. **Use Firestore** for database persistence
2. **Use Streamlit secrets** for credentials
3. **Enable rate limiting** to prevent abuse
4. **Set up monitoring** with health checks
5. **Use private repo** if handling sensitive data
6. **Test thoroughly** before sharing link

**Your app will be accessible at:**
`https://your-app-name.streamlit.app`

---

## 📞 **Need Help?**

**Streamlit Cloud Docs:**
- [Deploy an app](https://docs.streamlit.io/streamlit-community-cloud/deploy-your-app)
- [Secrets management](https://docs.streamlit.io/streamlit-community-cloud/deploy-your-app/secrets-management)
- [App settings](https://docs.streamlit.io/streamlit-community-cloud/manage-your-app)

**Common Issues:**
- Check app logs in Streamlit Cloud dashboard
- Verify secrets format exactly
- Test locally first with same secrets
- Use `st.write()` for debugging

---

**🎊 Your enterprise WAF Scanner is ready for Streamlit Cloud deployment!**
