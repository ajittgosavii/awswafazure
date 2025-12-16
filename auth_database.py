"""
Database Operations for User Management
Handles user data persistence with PostgreSQL or SQLite
"""

import streamlit as st
from typing import Optional, Dict, Any, List
from datetime import datetime
import json
import os

# Try to import database libraries
try:
    from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, Text, JSON
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker, Session
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    st.warning("⚠️ SQLAlchemy not installed. Database features disabled.")

Base = declarative_base() if SQLALCHEMY_AVAILABLE else None


class User(Base):
    """User model"""
    __tablename__ = 'users'
    
    id = Column(String(255), primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255))
    given_name = Column(String(255))
    surname = Column(String(255))
    job_title = Column(String(255))
    department = Column(String(255))
    office_location = Column(String(255))
    role = Column(String(50), default='viewer')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True)


class UserPreference(Base):
    """User preferences model"""
    __tablename__ = 'user_preferences'
    
    user_id = Column(String(255), primary_key=True)
    theme = Column(String(20), default='light')
    default_cloud = Column(String(20), default='aws')
    notifications_enabled = Column(Boolean, default=True)
    dashboard_layout = Column(String(20), default='default')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(Base):
    """Audit log model"""
    __tablename__ = 'audit_log'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255))
    event_type = Column(String(50))
    event_data = Column(Text)  # JSON string
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)


class DatabaseManager:
    """Database operations manager"""
    
    def __init__(self):
        """Initialize database connection"""
        self.engine = None
        self.Session = None
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize database connection"""
        if not SQLALCHEMY_AVAILABLE:
            return
        
        db_config = self._get_db_config()
        
        if db_config['type'] == 'postgresql':
            connection_string = (
                f"postgresql://{db_config['user']}:{db_config['password']}"
                f"@{db_config['host']}:{db_config['port']}/{db_config['name']}"
            )
        else:  # SQLite
            db_path = db_config.get('path', 'cloudidp_users.db')
            connection_string = f"sqlite:///{db_path}"
        
        try:
            self.engine = create_engine(connection_string)
            self.Session = sessionmaker(bind=self.engine)
            
            # Create tables if they don't exist
            Base.metadata.create_all(self.engine)
        except Exception as e:
            st.error(f"Database connection failed: {str(e)}")
    
    def _get_db_config(self) -> Dict[str, str]:
        """Get database configuration"""
        try:
            db_secrets = st.secrets.get('database', {})
            db_type = db_secrets.get('db_type', 'sqlite')
            
            if db_type == 'postgresql':
                return {
                    'type': 'postgresql',
                    'host': db_secrets.get('db_host', 'localhost'),
                    'port': db_secrets.get('db_port', '5432'),
                    'name': db_secrets.get('db_name', 'cloudidp'),
                    'user': db_secrets.get('db_user', 'cloudidp'),
                    'password': db_secrets.get('db_password', '')
                }
            else:
                return {
                    'type': 'sqlite',
                    'path': db_secrets.get('db_path', 'cloudidp_users.db')
                }
        except:
            return {'type': 'sqlite', 'path': 'cloudidp_users.db'}
    
    def get_session(self) -> Optional[Session]:
        """Get database session"""
        if self.Session:
            return self.Session()
        return None
    
    # User operations
    
    def create_or_update_user(self, user_info: Dict[str, Any]) -> bool:
        """Create or update user"""
        session = self.get_session()
        if not session:
            return False
        
        try:
            user = session.query(User).filter_by(id=user_info['id']).first()
            
            if user:
                # Update existing user
                user.email = user_info.get('email', user.email)
                user.name = user_info.get('name', user.name)
                user.given_name = user_info.get('given_name', user.given_name)
                user.surname = user_info.get('surname', user.surname)
                user.job_title = user_info.get('job_title', user.job_title)
                user.department = user_info.get('department', user.department)
                user.office_location = user_info.get('office_location', user.office_location)
                user.last_login = datetime.utcnow()
                user.updated_at = datetime.utcnow()
            else:
                # Create new user
                user = User(
                    id=user_info['id'],
                    email=user_info.get('email'),
                    name=user_info.get('name'),
                    given_name=user_info.get('given_name'),
                    surname=user_info.get('surname'),
                    job_title=user_info.get('job_title'),
                    department=user_info.get('department'),
                    office_location=user_info.get('office_location'),
                    role='viewer',  # Default role
                    last_login=datetime.utcnow()
                )
                session.add(user)
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            st.error(f"Failed to save user: {str(e)}")
            return False
        finally:
            session.close()
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        session = self.get_session()
        if not session:
            return None
        
        try:
            user = session.query(User).filter_by(id=user_id).first()
            if user:
                return {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'given_name': user.given_name,
                    'surname': user.surname,
                    'job_title': user.job_title,
                    'department': user.department,
                    'office_location': user.office_location,
                    'role': user.role,
                    'is_active': user.is_active,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                }
            return None
        except Exception as e:
            st.error(f"Failed to get user: {str(e)}")
            return None
        finally:
            session.close()
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        session = self.get_session()
        if not session:
            return None
        
        try:
            user = session.query(User).filter_by(email=email).first()
            if user:
                return self.get_user(user.id)
            return None
        except Exception as e:
            st.error(f"Failed to get user: {str(e)}")
            return None
        finally:
            session.close()
    
    def update_user_role(self, user_id: str, role: str) -> bool:
        """Update user role"""
        session = self.get_session()
        if not session:
            return False
        
        try:
            user = session.query(User).filter_by(id=user_id).first()
            if user:
                user.role = role
                user.updated_at = datetime.utcnow()
                session.commit()
                return True
            return False
        except Exception as e:
            session.rollback()
            st.error(f"Failed to update role: {str(e)}")
            return False
        finally:
            session.close()
    
    def get_all_users(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """Get all users"""
        session = self.get_session()
        if not session:
            return []
        
        try:
            query = session.query(User)
            if active_only:
                query = query.filter_by(is_active=True)
            
            users = query.all()
            return [
                {
                    'id': u.id,
                    'email': u.email,
                    'name': u.name,
                    'role': u.role,
                    'department': u.department,
                    'last_login': u.last_login.isoformat() if u.last_login else None
                }
                for u in users
            ]
        except Exception as e:
            st.error(f"Failed to get users: {str(e)}")
            return []
        finally:
            session.close()
    
    # User preferences operations
    
    def get_user_preferences(self, user_id: str) -> Dict[str, Any]:
        """Get user preferences"""
        session = self.get_session()
        if not session:
            return self._default_preferences()
        
        try:
            prefs = session.query(UserPreference).filter_by(user_id=user_id).first()
            if prefs:
                return {
                    'theme': prefs.theme,
                    'default_cloud': prefs.default_cloud,
                    'notifications_enabled': prefs.notifications_enabled,
                    'dashboard_layout': prefs.dashboard_layout
                }
            return self._default_preferences()
        except Exception as e:
            st.error(f"Failed to get preferences: {str(e)}")
            return self._default_preferences()
        finally:
            session.close()
    
    def save_user_preferences(self, user_id: str, preferences: Dict[str, Any]) -> bool:
        """Save user preferences"""
        session = self.get_session()
        if not session:
            return False
        
        try:
            prefs = session.query(UserPreference).filter_by(user_id=user_id).first()
            
            if prefs:
                # Update existing
                prefs.theme = preferences.get('theme', prefs.theme)
                prefs.default_cloud = preferences.get('default_cloud', prefs.default_cloud)
                prefs.notifications_enabled = preferences.get('notifications_enabled', prefs.notifications_enabled)
                prefs.dashboard_layout = preferences.get('dashboard_layout', prefs.dashboard_layout)
                prefs.updated_at = datetime.utcnow()
            else:
                # Create new
                prefs = UserPreference(
                    user_id=user_id,
                    theme=preferences.get('theme', 'light'),
                    default_cloud=preferences.get('default_cloud', 'aws'),
                    notifications_enabled=preferences.get('notifications_enabled', True),
                    dashboard_layout=preferences.get('dashboard_layout', 'default')
                )
                session.add(prefs)
            
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            st.error(f"Failed to save preferences: {str(e)}")
            return False
        finally:
            session.close()
    
    # Audit log operations
    
    def log_event(self, user_id: str, event_type: str, event_data: Dict[str, Any],
                   ip_address: str = None, user_agent: str = None) -> bool:
        """Log audit event"""
        session = self.get_session()
        if not session:
            return False
        
        try:
            log_entry = AuditLog(
                user_id=user_id,
                event_type=event_type,
                event_data=json.dumps(event_data),
                ip_address=ip_address or 'unknown',
                user_agent=user_agent or 'unknown'
            )
            session.add(log_entry)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            st.error(f"Failed to log event: {str(e)}")
            return False
        finally:
            session.close()
    
    def get_audit_logs(self, user_id: str = None, event_type: str = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit logs"""
        session = self.get_session()
        if not session:
            return []
        
        try:
            query = session.query(AuditLog)
            
            if user_id:
                query = query.filter_by(user_id=user_id)
            if event_type:
                query = query.filter_by(event_type=event_type)
            
            query = query.order_by(AuditLog.timestamp.desc()).limit(limit)
            logs = query.all()
            
            return [
                {
                    'user_id': log.user_id,
                    'event_type': log.event_type,
                    'event_data': json.loads(log.event_data) if log.event_data else {},
                    'ip_address': log.ip_address,
                    'timestamp': log.timestamp.isoformat() if log.timestamp else None
                }
                for log in logs
            ]
        except Exception as e:
            st.error(f"Failed to get audit logs: {str(e)}")
            return []
        finally:
            session.close()
    
    def _default_preferences(self) -> Dict[str, Any]:
        """Get default preferences"""
        return {
            'theme': 'light',
            'default_cloud': 'aws',
            'notifications_enabled': True,
            'dashboard_layout': 'default'
        }


# Initialize database manager
def get_database_manager() -> DatabaseManager:
    """Get or create database manager"""
    if 'db_manager' not in st.session_state:
        st.session_state.db_manager = DatabaseManager()
    return st.session_state.db_manager
