"""
WAF Scanner Database Module
Handles historical tracking, collaboration, and analytics
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import pandas as pd
from contextlib import contextmanager


class WAFDatabase:
    """Comprehensive database for WAF scanner with historical tracking"""
    
    def __init__(self, db_path: str = 'waf_scanner.db'):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize all database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scan history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    account_name TEXT,
                    scan_date TIMESTAMP NOT NULL,
                    scan_duration_seconds REAL,
                    total_findings INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    overall_waf_score REAL,
                    services_scanned INTEGER,
                    resources_scanned INTEGER,
                    scan_type TEXT,
                    user_email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_account_date (account_id, scan_date),
                    INDEX idx_scan_date (scan_date)
                )
            """)
            
            # Finding history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS finding_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    service TEXT,
                    resource TEXT,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    pillar TEXT,
                    status TEXT DEFAULT 'open',
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    resolved_date TIMESTAMP,
                    resolved_by TEXT,
                    false_positive BOOLEAN DEFAULT 0,
                    ignored BOOLEAN DEFAULT 0,
                    estimated_savings REAL DEFAULT 0,
                    risk_cost REAL DEFAULT 0,
                    remediation_effort TEXT,
                    compliance_frameworks TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id),
                    INDEX idx_finding_id (finding_id),
                    INDEX idx_status (status),
                    INDEX idx_severity (severity)
                )
            """)
            
            # Pillar scores history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pillar_scores_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    pillar TEXT NOT NULL,
                    score REAL NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id),
                    INDEX idx_pillar (pillar)
                )
            """)
            
            # Assignments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    assigned_to TEXT NOT NULL,
                    assigned_by TEXT NOT NULL,
                    assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    due_date TIMESTAMP,
                    priority TEXT DEFAULT 'normal',
                    status TEXT DEFAULT 'assigned',
                    notes TEXT,
                    INDEX idx_assigned_to (assigned_to),
                    INDEX idx_finding_id (finding_id)
                )
            """)
            
            # Comments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    author TEXT NOT NULL,
                    comment_text TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    edited BOOLEAN DEFAULT 0,
                    edited_timestamp TIMESTAMP,
                    INDEX idx_finding_id (finding_id)
                )
            """)
            
            # Status updates table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS status_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT,
                    INDEX idx_finding_id (finding_id)
                )
            """)
            
            # Remediation actions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_status TEXT DEFAULT 'pending',
                    initiated_by TEXT,
                    initiated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    rollback_available BOOLEAN DEFAULT 1,
                    backup_id TEXT,
                    terraform_plan TEXT,
                    verification_status TEXT,
                    error_message TEXT,
                    INDEX idx_finding_id (finding_id),
                    INDEX idx_status (action_status)
                )
            """)
            
            # Compliance mappings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS compliance_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_type TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    requirement_id TEXT NOT NULL,
                    requirement_description TEXT,
                    severity_impact TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_finding_type (finding_type),
                    INDEX idx_framework (framework)
                )
            """)
            
            # Cost impact history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cost_impact_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    waste_monthly REAL DEFAULT 0,
                    waste_annual REAL DEFAULT 0,
                    risk_cost REAL DEFAULT 0,
                    total_impact REAL DEFAULT 0,
                    calculation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id),
                    INDEX idx_scan_id (scan_id)
                )
            """)
            
            # Resource dependencies table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS resource_dependencies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id TEXT NOT NULL,
                    source_resource_id TEXT NOT NULL,
                    source_resource_type TEXT,
                    source_service TEXT,
                    target_resource_id TEXT NOT NULL,
                    target_resource_type TEXT,
                    target_service TEXT,
                    dependency_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_source (source_resource_id),
                    INDEX idx_target (target_resource_id)
                )
            """)
            
            # Notifications table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_type TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    subject TEXT,
                    message TEXT,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    delivery_status TEXT DEFAULT 'pending',
                    channel TEXT,
                    metadata TEXT,
                    INDEX idx_recipient (recipient),
                    INDEX idx_type (notification_type)
                )
            """)
            
            # User preferences table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_preferences (
                    user_email TEXT PRIMARY KEY,
                    notification_email BOOLEAN DEFAULT 1,
                    notification_slack BOOLEAN DEFAULT 0,
                    notification_teams BOOLEAN DEFAULT 0,
                    daily_digest BOOLEAN DEFAULT 1,
                    critical_alerts BOOLEAN DEFAULT 1,
                    slack_user_id TEXT,
                    teams_user_id TEXT,
                    timezone TEXT DEFAULT 'UTC',
                    preferences_json TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
    
    # ==================== SCAN HISTORY METHODS ====================
    
    def store_scan(self, scan_result: Dict) -> str:
        """Store scan results in database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            scan_id = scan_result.get('scan_id', datetime.now().strftime('%Y%m%d_%H%M%S'))
            
            cursor.execute("""
                INSERT INTO scan_history (
                    scan_id, account_id, account_name, scan_date,
                    scan_duration_seconds, total_findings,
                    critical_count, high_count, medium_count, low_count,
                    overall_waf_score, services_scanned, resources_scanned,
                    scan_type, user_email
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                scan_result.get('account_id'),
                scan_result.get('account_name'),
                scan_result.get('scan_date', datetime.now()),
                scan_result.get('scan_duration_seconds', 0),
                scan_result.get('total_findings', 0),
                scan_result.get('critical_count', 0),
                scan_result.get('high_count', 0),
                scan_result.get('medium_count', 0),
                scan_result.get('low_count', 0),
                scan_result.get('overall_waf_score', 0),
                scan_result.get('services_scanned', 0),
                scan_result.get('resources_scanned', 0),
                scan_result.get('scan_type', 'full'),
                scan_result.get('user_email')
            ))
            
            # Store pillar scores
            for pillar, data in scan_result.get('pillar_distribution', {}).items():
                cursor.execute("""
                    INSERT INTO pillar_scores_history (
                        scan_id, pillar, score, findings_count,
                        critical_count, high_count, medium_count, low_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    pillar,
                    data.get('score', 0),
                    data.get('count', 0),
                    data.get('critical', 0),
                    data.get('high', 0),
                    data.get('medium', 0),
                    data.get('low', 0)
                ))
            
            # Store findings
            for finding in scan_result.get('findings', []):
                self._store_finding(cursor, scan_id, scan_result['account_id'], finding)
            
            return scan_id
    
    def _store_finding(self, cursor, scan_id: str, account_id: str, finding: Dict):
        """Store individual finding with lifecycle tracking"""
        finding_id = finding.get('id', finding.get('finding_id'))
        
        # Check if finding exists
        cursor.execute("""
            SELECT id, first_seen FROM finding_history 
            WHERE finding_id = ? AND account_id = ?
        """, (finding_id, account_id))
        
        existing = cursor.fetchone()
        
        compliance_frameworks = json.dumps(finding.get('compliance_frameworks', []))
        
        if existing:
            # Update existing finding
            cursor.execute("""
                UPDATE finding_history 
                SET last_seen = ?, scan_id = ?, severity = ?, 
                    status = CASE WHEN status = 'resolved' THEN 'reopened' ELSE status END,
                    estimated_savings = ?, risk_cost = ?,
                    compliance_frameworks = ?
                WHERE finding_id = ? AND account_id = ?
            """, (
                datetime.now(),
                scan_id,
                finding.get('severity'),
                finding.get('estimated_savings', 0),
                finding.get('risk_cost', 0),
                compliance_frameworks,
                finding_id,
                account_id
            ))
        else:
            # Insert new finding
            cursor.execute("""
                INSERT INTO finding_history (
                    finding_id, scan_id, account_id, service, resource,
                    severity, title, description, pillar, status,
                    first_seen, last_seen, estimated_savings, risk_cost,
                    remediation_effort, compliance_frameworks
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id,
                scan_id,
                account_id,
                finding.get('service'),
                finding.get('resource'),
                finding.get('severity'),
                finding.get('title'),
                finding.get('description'),
                finding.get('pillar'),
                'open',
                datetime.now(),
                datetime.now(),
                finding.get('estimated_savings', 0),
                finding.get('risk_cost', 0),
                finding.get('remediation_effort'),
                compliance_frameworks
            ))
    
    def get_trend_data(self, account_id: str, days: int = 30) -> pd.DataFrame:
        """Get trend data for specified period"""
        with self.get_connection() as conn:
            query = """
                SELECT 
                    scan_date,
                    total_findings,
                    critical_count,
                    high_count,
                    medium_count,
                    low_count,
                    overall_waf_score
                FROM scan_history
                WHERE account_id = ?
                AND scan_date >= datetime('now', '-{} days')
                ORDER BY scan_date
            """.format(days)
            
            return pd.read_sql_query(query, conn, params=(account_id,))
    
    def get_pillar_trends(self, account_id: str, days: int = 30) -> pd.DataFrame:
        """Get pillar score trends"""
        with self.get_connection() as conn:
            query = """
                SELECT 
                    sh.scan_date,
                    psh.pillar,
                    psh.score,
                    psh.findings_count
                FROM pillar_scores_history psh
                JOIN scan_history sh ON psh.scan_id = sh.scan_id
                WHERE sh.account_id = ?
                AND sh.scan_date >= datetime('now', '-{} days')
                ORDER BY sh.scan_date, psh.pillar
            """.format(days)
            
            return pd.read_sql_query(query, conn, params=(account_id,))
    
    def get_finding_age_stats(self, account_id: Optional[str] = None) -> pd.DataFrame:
        """Get statistics on finding ages"""
        with self.get_connection() as conn:
            where_clause = "WHERE account_id = ?" if account_id else ""
            params = (account_id,) if account_id else ()
            
            query = f"""
                SELECT 
                    finding_id,
                    severity,
                    title,
                    first_seen,
                    status,
                    julianday('now') - julianday(first_seen) as age_days,
                    CASE 
                        WHEN julianday('now') - julianday(first_seen) > 90 THEN 'critical_age'
                        WHEN julianday('now') - julianday(first_seen) > 30 THEN 'high_age'
                        WHEN julianday('now') - julianday(first_seen) > 7 THEN 'medium_age'
                        ELSE 'new'
                    END as age_category
                FROM finding_history
                {where_clause}
                AND status = 'open'
                ORDER BY age_days DESC
            """
            
            return pd.read_sql_query(query, conn, params=params)
    
    # ==================== COLLABORATION METHODS ====================
    
    def assign_finding(self, finding_id: str, assigned_to: str, assigned_by: str, 
                      priority: str = 'normal', due_days: int = 7, notes: str = '') -> int:
        """Assign finding to team member"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            due_date = datetime.now() + timedelta(days=due_days)
            
            cursor.execute("""
                INSERT INTO assignments (
                    finding_id, assigned_to, assigned_by, due_date, priority, notes
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (finding_id, assigned_to, assigned_by, due_date, priority, notes))
            
            # Update finding status
            cursor.execute("""
                UPDATE finding_history 
                SET status = 'assigned'
                WHERE finding_id = ?
            """, (finding_id,))
            
            return cursor.lastrowid
    
    def add_comment(self, finding_id: str, author: str, comment_text: str) -> int:
        """Add comment to finding"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO comments (finding_id, author, comment_text)
                VALUES (?, ?, ?)
            """, (finding_id, author, comment_text))
            
            return cursor.lastrowid
    
    def get_comments(self, finding_id: str) -> List[Dict]:
        """Get all comments for a finding"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT author, comment_text, timestamp, edited
                FROM comments
                WHERE finding_id = ?
                ORDER BY timestamp DESC
            """, (finding_id,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def update_finding_status(self, finding_id: str, new_status: str, 
                            updated_by: str, notes: str = '') -> int:
        """Update finding status with audit trail"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get current status
            cursor.execute("""
                SELECT status FROM finding_history WHERE finding_id = ?
            """, (finding_id,))
            
            row = cursor.fetchone()
            old_status = row['status'] if row else None
            
            # Update status
            cursor.execute("""
                UPDATE finding_history 
                SET status = ?,
                    resolved_date = CASE WHEN ? = 'resolved' THEN CURRENT_TIMESTAMP ELSE NULL END,
                    resolved_by = CASE WHEN ? = 'resolved' THEN ? ELSE NULL END
                WHERE finding_id = ?
            """, (new_status, new_status, new_status, updated_by, finding_id))
            
            # Log status change
            cursor.execute("""
                INSERT INTO status_updates (
                    finding_id, old_status, new_status, updated_by, notes
                ) VALUES (?, ?, ?, ?, ?)
            """, (finding_id, old_status, new_status, updated_by, notes))
            
            return cursor.lastrowid
    
    def get_assigned_findings(self, user_email: str) -> List[Dict]:
        """Get all findings assigned to a user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    fh.finding_id,
                    fh.severity,
                    fh.title,
                    fh.service,
                    fh.status,
                    a.assigned_date,
                    a.due_date,
                    a.priority,
                    a.notes
                FROM finding_history fh
                JOIN assignments a ON fh.finding_id = a.finding_id
                WHERE a.assigned_to = ?
                AND fh.status NOT IN ('resolved', 'ignored')
                ORDER BY a.due_date
            """, (user_email,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== ANALYTICS METHODS ====================
    
    def get_summary_stats(self, account_id: Optional[str] = None) -> Dict:
        """Get summary statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            where_clause = "WHERE account_id = ?" if account_id else ""
            params = (account_id,) if account_id else ()
            
            # Overall stats
            cursor.execute(f"""
                SELECT 
                    COUNT(*) as total_scans,
                    MAX(scan_date) as last_scan,
                    AVG(overall_waf_score) as avg_waf_score
                FROM scan_history
                {where_clause}
            """, params)
            
            scan_stats = dict(cursor.fetchone())
            
            # Finding stats
            cursor.execute(f"""
                SELECT 
                    COUNT(*) as total_findings,
                    SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_findings,
                    SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_findings,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_findings,
                    AVG(CASE WHEN status = 'resolved' 
                        THEN julianday(resolved_date) - julianday(first_seen) 
                        ELSE NULL END) as avg_resolution_days
                FROM finding_history
                {where_clause}
            """, params)
            
            finding_stats = dict(cursor.fetchone())
            
            return {**scan_stats, **finding_stats}
    
    def get_cost_impact_summary(self, account_id: Optional[str] = None) -> Dict:
        """Get total cost impact across all findings"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            where_clause = "WHERE fh.account_id = ?" if account_id else ""
            params = (account_id,) if account_id else ()
            
            cursor.execute(f"""
                SELECT 
                    SUM(estimated_savings) as total_waste_monthly,
                    SUM(estimated_savings * 12) as total_waste_annual,
                    SUM(risk_cost) as total_risk_exposure,
                    COUNT(*) as findings_with_cost_impact
                FROM finding_history fh
                {where_clause}
                AND status = 'open'
                AND (estimated_savings > 0 OR risk_cost > 0)
            """, params)
            
            return dict(cursor.fetchone())
    
    def close(self):
        """Close database connection"""
        pass  # Using context managers, no persistent connection


# Example usage
if __name__ == "__main__":
    db = WAFDatabase()
    
    # Example: Store scan
    scan_result = {
        'scan_id': '20251212_120000',
        'account_id': '123456789012',
        'account_name': 'Production',
        'scan_date': datetime.now(),
        'total_findings': 45,
        'critical_count': 3,
        'high_count': 12,
        'medium_count': 20,
        'low_count': 10,
        'overall_waf_score': 72.5,
        'pillar_distribution': {
            'Security': {'score': 65, 'count': 15},
            'Reliability': {'score': 80, 'count': 10}
        },
        'findings': []
    }
    
    scan_id = db.store_scan(scan_result)
    print(f"Stored scan: {scan_id}")
    
    # Example: Get trends
    trends = db.get_trend_data('123456789012', days=30)
    print(f"\nTrend data shape: {trends.shape}")
    
    # Example: Get summary stats
    stats = db.get_summary_stats()
    print(f"\nSummary stats: {stats}")
