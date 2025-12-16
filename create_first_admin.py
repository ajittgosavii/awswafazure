"""
Create First Admin User for Firebase Authentication
Run this script once to create your initial admin account
"""

import firebase_admin
from firebase_admin import credentials, auth, firestore
from datetime import datetime
import sys

def create_first_admin():
    """Create the first admin user"""
    
    print("=" * 60)
    print("Create First Admin User for AWS WAF Advisor")
    print("=" * 60)
    print()
    
    # Get service account key path
    service_account_path = input("Enter path to Firebase service account JSON file: ").strip()
    
    try:
        # Initialize Firebase
        cred = credentials.Certificate(service_account_path)
        firebase_admin.initialize_app(cred)
        print("✅ Firebase initialized successfully")
        print()
    except Exception as e:
        print(f"❌ Error initializing Firebase: {str(e)}")
        sys.exit(1)
    
    # Get admin details
    print("Enter admin user details:")
    admin_email = input("Email: ").strip()
    admin_name = input("Full Name: ").strip()
    admin_password = input("Password (min 6 characters): ").strip()
    
    # Validation
    if not admin_email or '@' not in admin_email:
        print("❌ Invalid email address")
        sys.exit(1)
    
    if not admin_name:
        print("❌ Name is required")
        sys.exit(1)
    
    if len(admin_password) < 6:
        print("❌ Password must be at least 6 characters")
        sys.exit(1)
    
    print()
    print("Creating admin user...")
    
    try:
        # Create user in Firebase Authentication
        user = auth.create_user(
            email=admin_email,
            password=admin_password,
            display_name=admin_name,
            email_verified=True  # Set to True for first admin
        )
        print(f"✅ User created in Firebase Auth (UID: {user.uid})")
        
        # Create user profile in Firestore
        db = firestore.client()
        user_data = {
            'uid': user.uid,
            'email': admin_email,
            'display_name': admin_name,
            'role': 'admin',
            'created_at': datetime.now().isoformat(),
            'created_by': 'system',
            'last_login': None,
            'active': True,
            'metadata': {
                'assessments_count': 0,
                'last_activity': None
            }
        }
        
        db.collection('users').document(user.uid).set(user_data)
        print(f"✅ User profile created in Firestore")
        
        print()
        print("=" * 60)
        print("SUCCESS! Admin user created successfully! 🎉")
        print("=" * 60)
        print()
        print("Admin Login Credentials:")
        print(f"  Email:    {admin_email}")
        print(f"  Password: {admin_password}")
        print(f"  Role:     Admin")
        print(f"  UID:      {user.uid}")
        print()
        print("⚠️  IMPORTANT: Save these credentials securely!")
        print("⚠️  Change the password after first login")
        print()
        print("Next steps:")
        print("1. Log in to your Streamlit app with these credentials")
        print("2. Navigate to User Management tab")
        print("3. Create additional users as needed")
        print()
        
    except auth.EmailAlreadyExistsError:
        print(f"❌ Error: User with email {admin_email} already exists")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error creating user: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        create_first_admin()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(0)
