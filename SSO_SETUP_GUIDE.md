# SSO & User Management Setup Guide

## Overview

AWS WAF Scanner Enterprise includes built-in SSO authentication with Firebase and comprehensive user management capabilities. This guide explains how to set up and configure the authentication system.

## Features

### Authentication Methods
- **Email/Password** - Traditional login with email and password
- **Google SSO** - Sign in with Google (requires Firebase)
- **Local Demo Mode** - Works without Firebase for testing

### Role-Based Access Control (RBAC)

| Role | Level | Description | Key Permissions |
|------|-------|-------------|-----------------|
| **Super Admin** | 5 | Full system control | Everything + manage all users, organizations, settings |
| **Admin** | 4 | Organization admin | Manage org users, all scans, integrations |
| **Manager** | 3 | Team leader | View team data, run scans, export data |
| **User** | 2 | Standard user | Run scans, view own data, export |
| **Viewer** | 1 | Read-only | View data, demo mode only |
| **Guest** | 0 | Demo only | Demo mode only, limited access |

### Tab Access by Role

| Tab | Guest | Viewer | User | Manager | Admin | Super Admin |
|-----|-------|--------|------|---------|-------|-------------|
| WAF Scanner | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| AWS Connector | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| WAF Assessment | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Architecture Designer | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Cost Optimization | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| EKS Modernization | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Compliance | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| AI Assistant | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Admin Panel | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |

---

## Quick Start (Demo Mode)

The application works immediately without Firebase configuration using local authentication:

### Default Admin Account
```
Email: admin@wafscanner.local
Password: Admin@123
```

This account has Super Admin privileges and can create additional users.

---

## Firebase Setup (Production)

### Step 1: Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add Project"
3. Enter a project name (e.g., "waf-scanner-enterprise")
4. Disable Google Analytics (optional)
5. Click "Create Project"

### Step 2: Enable Authentication

1. In Firebase Console, go to **Authentication** > **Sign-in method**
2. Enable **Email/Password**
3. (Optional) Enable **Google** for SSO

### Step 3: Get API Key

1. Go to **Project Settings** (gear icon)
2. Under **General** tab, find "Web API Key"
3. Copy this key

### Step 4: Generate Service Account Key

1. Go to **Project Settings** > **Service accounts**
2. Click "Generate new private key"
3. Download the JSON file
4. Keep this file secure!

### Step 5: Configure Streamlit Secrets

Add to `.streamlit/secrets.toml`:

```toml
[app]
require_auth = true  # Enable authentication

[firebase]
api_key = "AIzaSy..."  # From Step 3

[firebase.service_account]
type = "service_account"
project_id = "your-project-id"
private_key_id = "abc123..."
private_key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
client_email = "firebase-adminsdk-xxxxx@your-project.iam.gserviceaccount.com"
client_id = "123456789..."
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
```

### Step 6: Create Firestore Database

1. Go to **Firestore Database** in Firebase Console
2. Click "Create database"
3. Choose "Start in production mode"
4. Select a location

---

## Admin Panel Features

### User Management

Admins can:
- **Create Users** - Add new users with specific roles
- **Update Users** - Change roles, enable/disable accounts
- **Delete Users** - Deactivate user accounts
- **View All Users** - Filter by role, status, search

### Organization Management

- Create and manage organizations
- Assign users to organizations
- Set plan limits (free, pro, enterprise)

### Audit Logs

Track all user actions:
- Login/logout events
- User creation/modification
- Data exports
- Scan executions

### API Key Management

- Generate API keys for programmatic access
- Revoke keys as needed
- Track key usage

### System Settings

- Firebase connection status
- Application settings
- Feature toggles

---

## Configuration Options

### secrets.toml Settings

```toml
[app]
require_auth = true      # Require login (default: false)
allow_guest_mode = true  # Allow demo without login (default: true)
default_to_demo = true   # Start in demo mode (default: true)
```

### Environment Variables

You can also use environment variables:
```bash
REQUIRE_AUTH=true
ALLOW_GUEST_MODE=true
```

---

## Security Best Practices

### 1. Use Strong Passwords
- Minimum 8 characters
- Mix of letters, numbers, symbols
- Don't reuse passwords

### 2. Enable 2FA in Firebase
- Go to Firebase Console > Authentication
- Enable multi-factor authentication

### 3. Regular Audit Reviews
- Review audit logs weekly
- Check for unusual activity
- Remove inactive users

### 4. Least Privilege Principle
- Assign minimum required roles
- Use Viewer role for read-only access
- Reserve Admin for necessary users only

### 5. Secure Secrets
- Never commit secrets.toml to Git
- Use Streamlit Cloud secrets management
- Rotate Firebase keys periodically

---

## Troubleshooting

### "Firebase not configured"
- Check that `[firebase]` section exists in secrets.toml
- Verify API key is correct
- Ensure service account JSON is properly formatted

### "User profile not found"
- User exists in Firebase Auth but not Firestore
- Create user profile in Firestore 'users' collection

### "Invalid email or password"
- Check credentials are correct
- Verify user exists in Firebase Auth
- Check if account is disabled

### "Access denied"
- User role doesn't have required permission
- Check TAB_ACCESS configuration
- Contact administrator

---

## API Reference

### Authentication

```python
from sso_admin_manager import get_auth_manager, SessionManager

# Authenticate
auth_mgr = get_auth_manager()
success, message, user = auth_mgr.authenticate(email, password)

# Check session
if SessionManager.is_authenticated():
    user = SessionManager.get_current_user()
    print(f"Logged in as: {user.email}")

# Check permissions
if SessionManager.has_permission("run_scans"):
    # Run scan
    pass
```

### User Management

```python
from sso_admin_manager import get_auth_manager

auth_mgr = get_auth_manager()

# Create user
success, msg, user = auth_mgr.create_user(
    email="user@company.com",
    password="SecurePass123",
    display_name="John Doe",
    role="user",
    organization_id="default-org"
)

# Update user
success, msg = auth_mgr.update_user(uid, {"role": "manager"})

# Deactivate user
success, msg = auth_mgr.delete_user(uid)

# List all users
users = auth_mgr.get_all_users()
```

---

## Support

For issues or questions:
1. Check this documentation
2. Review Streamlit logs
3. Check Firebase Console for auth errors
4. Contact system administrator
