"""
Database Service - Persistent Storage Layer
Handles storage of blueprints, configurations, and operational history
"""

import streamlit as st
import json
import sqlite3
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import os

class DatabaseService:
    """Database service for persistent storage"""
    
    def __init__(self, db_path: str = None):
        """
        Initialize database service
        
        Args:
            db_path: Path to SQLite database file
        """
        if db_path is None:
            # Use a default path in user's home directory or temp
            db_dir = Path.home() / '.cloudidp'
            db_dir.mkdir(exist_ok=True)
            db_path = str(db_dir / 'cloudidp.db')
        
        self.db_path = db_path
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database schema"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Blueprints table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blueprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    category TEXT,
                    template_data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by TEXT,
                    tags TEXT
                )
            ''')
            
            # Deployments table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS deployments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    deployment_id TEXT NOT NULL UNIQUE,
                    blueprint_id INTEGER,
                    account_id TEXT,
                    account_name TEXT,
                    region TEXT,
                    status TEXT,
                    stack_name TEXT,
                    parameters TEXT,
                    outputs TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by TEXT,
                    FOREIGN KEY (blueprint_id) REFERENCES blueprints (id)
                )
            ''')
            
            # Operations history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS operations_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_type TEXT NOT NULL,
                    operation_name TEXT NOT NULL,
                    account_id TEXT,
                    account_name TEXT,
                    region TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    status TEXT,
                    details TEXT,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    executed_by TEXT,
                    duration_seconds INTEGER
                )
            ''')
            
            # Cost data table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cost_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT,
                    account_name TEXT,
                    service TEXT,
                    cost_date DATE,
                    cost_amount REAL,
                    currency TEXT DEFAULT 'USD',
                    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Account configurations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS account_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT NOT NULL UNIQUE,
                    account_name TEXT NOT NULL,
                    configuration TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            st.error(f"Database initialization error: {e}")
    
    # ========== Blueprint Operations ==========
    
    def save_blueprint(
        self, 
        name: str,
        description: str,
        category: str,
        template_data: Dict,
        created_by: str = "system",
        tags: List[str] = None
    ) -> Optional[int]:
        """Save a new blueprint"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            tags_str = json.dumps(tags) if tags else None
            template_str = json.dumps(template_data)
            
            cursor.execute('''
                INSERT INTO blueprints (name, description, category, template_data, created_by, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, description, category, template_str, created_by, tags_str))
            
            blueprint_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return blueprint_id
        except sqlite3.IntegrityError:
            st.error(f"Blueprint '{name}' already exists")
            return None
        except Exception as e:
            st.error(f"Error saving blueprint: {e}")
            return None
    
    def get_blueprints(self, category: str = None) -> List[Dict]:
        """Get all blueprints, optionally filtered by category"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if category:
                cursor.execute('''
                    SELECT id, name, description, category, template_data, created_at, created_by, tags
                    FROM blueprints WHERE category = ?
                    ORDER BY created_at DESC
                ''', (category,))
            else:
                cursor.execute('''
                    SELECT id, name, description, category, template_data, created_at, created_by, tags
                    FROM blueprints
                    ORDER BY created_at DESC
                ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            blueprints = []
            for row in rows:
                blueprints.append({
                    'id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'category': row[3],
                    'template_data': json.loads(row[4]),
                    'created_at': row[5],
                    'created_by': row[6],
                    'tags': json.loads(row[7]) if row[7] else []
                })
            
            return blueprints
        except Exception as e:
            st.error(f"Error fetching blueprints: {e}")
            return []
    
    def get_blueprint_by_name(self, name: str) -> Optional[Dict]:
        """Get a specific blueprint by name"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, name, description, category, template_data, created_at, created_by, tags
                FROM blueprints WHERE name = ?
            ''', (name,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'category': row[3],
                    'template_data': json.loads(row[4]),
                    'created_at': row[5],
                    'created_by': row[6],
                    'tags': json.loads(row[7]) if row[7] else []
                }
            return None
        except Exception as e:
            st.error(f"Error fetching blueprint: {e}")
            return None
    
    def update_blueprint(self, blueprint_id: int, **kwargs) -> bool:
        """Update an existing blueprint"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            updates = []
            values = []
            
            for key, value in kwargs.items():
                if key in ['name', 'description', 'category', 'created_by']:
                    updates.append(f"{key} = ?")
                    values.append(value)
                elif key == 'template_data':
                    updates.append("template_data = ?")
                    values.append(json.dumps(value))
                elif key == 'tags':
                    updates.append("tags = ?")
                    values.append(json.dumps(value))
            
            if updates:
                updates.append("updated_at = CURRENT_TIMESTAMP")
                values.append(blueprint_id)
                
                query = f"UPDATE blueprints SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, values)
                
                conn.commit()
            
            conn.close()
            return True
        except Exception as e:
            st.error(f"Error updating blueprint: {e}")
            return False
    
    def delete_blueprint(self, blueprint_id: int) -> bool:
        """Delete a blueprint"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM blueprints WHERE id = ?', (blueprint_id,))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Error deleting blueprint: {e}")
            return False
    
    # ========== Deployment Operations ==========
    
    def save_deployment(
        self,
        deployment_id: str,
        blueprint_id: int,
        account_id: str,
        account_name: str,
        region: str,
        status: str,
        stack_name: str = None,
        parameters: Dict = None,
        created_by: str = "system"
    ) -> Optional[int]:
        """Save deployment record"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            params_str = json.dumps(parameters) if parameters else None
            
            cursor.execute('''
                INSERT INTO deployments 
                (deployment_id, blueprint_id, account_id, account_name, region, status, stack_name, parameters, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (deployment_id, blueprint_id, account_id, account_name, region, status, stack_name, params_str, created_by))
            
            dep_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return dep_id
        except Exception as e:
            st.error(f"Error saving deployment: {e}")
            return None
    
    def get_deployments(self, account_id: str = None, status: str = None) -> List[Dict]:
        """Get deployment history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = 'SELECT * FROM deployments WHERE 1=1'
            params = []
            
            if account_id:
                query += ' AND account_id = ?'
                params.append(account_id)
            
            if status:
                query += ' AND status = ?'
                params.append(status)
            
            query += ' ORDER BY created_at DESC'
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            deployments = []
            for row in rows:
                deployments.append({
                    'id': row[0],
                    'deployment_id': row[1],
                    'blueprint_id': row[2],
                    'account_id': row[3],
                    'account_name': row[4],
                    'region': row[5],
                    'status': row[6],
                    'stack_name': row[7],
                    'parameters': json.loads(row[8]) if row[8] else {},
                    'outputs': json.loads(row[9]) if row[9] else {},
                    'created_at': row[10],
                    'updated_at': row[11],
                    'created_by': row[12]
                })
            
            return deployments
        except Exception as e:
            st.error(f"Error fetching deployments: {e}")
            return []
    
    # ========== Operations History ==========
    
    def log_operation(
        self,
        operation_type: str,
        operation_name: str,
        account_id: str,
        account_name: str,
        region: str,
        resource_type: str = None,
        resource_id: str = None,
        status: str = "success",
        details: Dict = None,
        executed_by: str = "system",
        duration_seconds: int = None
    ) -> bool:
        """Log an operation to history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            details_str = json.dumps(details) if details else None
            
            cursor.execute('''
                INSERT INTO operations_history
                (operation_type, operation_name, account_id, account_name, region, 
                 resource_type, resource_id, status, details, executed_by, duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (operation_type, operation_name, account_id, account_name, region,
                  resource_type, resource_id, status, details_str, executed_by, duration_seconds))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Error logging operation: {e}")
            return False
    
    def get_operations_history(
        self,
        account_id: str = None,
        operation_type: str = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get operations history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = 'SELECT * FROM operations_history WHERE 1=1'
            params = []
            
            if account_id:
                query += ' AND account_id = ?'
                params.append(account_id)
            
            if operation_type:
                query += ' AND operation_type = ?'
                params.append(operation_type)
            
            query += ' ORDER BY executed_at DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            
            operations = []
            for row in rows:
                operations.append({
                    'id': row[0],
                    'operation_type': row[1],
                    'operation_name': row[2],
                    'account_id': row[3],
                    'account_name': row[4],
                    'region': row[5],
                    'resource_type': row[6],
                    'resource_id': row[7],
                    'status': row[8],
                    'details': json.loads(row[9]) if row[9] else {},
                    'executed_at': row[10],
                    'executed_by': row[11],
                    'duration_seconds': row[12]
                })
            
            return operations
        except Exception as e:
            st.error(f"Error fetching operations history: {e}")
            return []


# Global instance
@st.cache_resource
def get_database_service() -> DatabaseService:
    """Get cached database service instance"""
    return DatabaseService()
