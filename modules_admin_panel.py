"""
Admin Panel Module
User management and platform administration with Firebase Realtime Database
Permission: * (admin only)
"""

import streamlit as st
from auth_azure_sso import require_permission
from auth_database_firebase import get_database_manager
from datetime import datetime, timedelta
import pandas as pd
from typing import Dict, List

class AdminPanelModule:
    """Admin panel for user management and platform administration"""
    
    @staticmethod
    @require_permission('*')
    def render():
        """Render admin panel - admins only"""
        st.title("👨‍💼 Admin Panel")
        st.caption("User management and platform administration")
        
        # Get database manager
        db_manager = get_database_manager()
        if not db_manager:
            st.error("❌ Database connection not available")
            return
        
        # Get current user info
        user_manager = st.session_state.get('user_manager')
        current_user = user_manager.get_current_user() if user_manager else None
        
        if not current_user:
            st.error("❌ User session not found")
            return
        
        st.info(f"👤 Logged in as: **{current_user['name']}** ({current_user['email']})")
        
        # Main tabs
        tabs = st.tabs([
            "👥 Users", 
            "🎭 Roles", 
            "📊 Analytics", 
            "📜 Audit Logs",
            "⚙️ Settings"
        ])
        
        # Tab 1: User Management
        with tabs[0]:
            AdminPanelModule._render_user_management(db_manager, current_user)
        
        # Tab 2: Role Management
        with tabs[1]:
            AdminPanelModule._render_role_management(db_manager)
        
        # Tab 3: Analytics
        with tabs[2]:
            AdminPanelModule._render_analytics(db_manager)
        
        # Tab 4: Audit Logs
        with tabs[3]:
            AdminPanelModule._render_audit_logs(db_manager)
        
        # Tab 5: Settings
        with tabs[4]:
            AdminPanelModule._render_settings(db_manager, current_user)
    
    @staticmethod
    def _render_user_management(db_manager, current_user):
        """Render user management tab"""
        st.markdown("### 👥 User Management")
        
        # Search and filters
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            search_query = st.text_input("🔍 Search users", placeholder="Search by name or email...")
        with col2:
            role_filter = st.selectbox("Filter by Role", ["All", "admin", "architect", "developer", "finops", "security", "viewer"])
        with col3:
            status_filter = st.selectbox("Status", ["All", "Active", "Inactive"])
        
        # Get all users
        try:
            all_users = db_manager.get_all_users(active_only=False)
            
            # Apply filters
            filtered_users = all_users
            
            # Search filter
            if search_query:
                filtered_users = [
                    u for u in filtered_users 
                    if search_query.lower() in u.get('name', '').lower() 
                    or search_query.lower() in u.get('email', '').lower()
                ]
            
            # Role filter
            if role_filter != "All":
                filtered_users = [u for u in filtered_users if u.get('role') == role_filter]
            
            # Status filter
            if status_filter == "Active":
                filtered_users = [u for u in filtered_users if u.get('is_active', True)]
            elif status_filter == "Inactive":
                filtered_users = [u for u in filtered_users if not u.get('is_active', True)]
            
            # Display summary
            st.markdown(f"**Total Users:** {len(all_users)} | **Filtered:** {len(filtered_users)}")
            
            if len(filtered_users) == 0:
                st.info("No users found matching your filters.")
                return
            
            # Display users
            for user in filtered_users:
                AdminPanelModule._render_user_card(db_manager, user, current_user)
                
        except Exception as e:
            st.error(f"Failed to load users: {str(e)}")
    
    @staticmethod
    def _render_user_card(db_manager, user, current_user):
        """Render individual user card with management options"""
        
        is_active = user.get('is_active', True)
        is_current_user = user['id'] == current_user['id']
        
        # Status indicator
        status_color = "🟢" if is_active else "🔴"
        status_text = "Active" if is_active else "Inactive"
        
        with st.expander(f"{status_color} **{user.get('name', 'Unknown')}** ({user.get('email', 'No email')}) - *{user.get('role', 'viewer').title()}*"):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"""
                **User ID:** `{user['id'][:20]}...`  
                **Email:** {user.get('email', 'N/A')}  
                **Name:** {user.get('name', 'N/A')}  
                **Department:** {user.get('department', 'N/A')}  
                **Job Title:** {user.get('job_title', 'N/A')}  
                **Status:** {status_text}  
                **Created:** {user.get('created_at', 'N/A')[:10] if user.get('created_at') else 'N/A'}  
                **Last Login:** {user.get('last_login', 'N/A')[:16] if user.get('last_login') else 'Never'}  
                """)
            
            with col2:
                st.markdown("#### Actions")
                
                # Role change
                current_role = user.get('role', 'viewer')
                new_role = st.selectbox(
                    "Change Role",
                    ["admin", "architect", "developer", "finops", "security", "viewer"],
                    index=["admin", "architect", "developer", "finops", "security", "viewer"].index(current_role),
                    key=f"role_{user['id']}",
                    disabled=is_current_user
                )
                
                if new_role != current_role:
                    if st.button("✅ Update Role", key=f"update_role_{user['id']}", disabled=is_current_user):
                        if db_manager.update_user_role(user['id'], new_role):
                            # Log the change
                            db_manager.log_event(
                                user_id=current_user['id'],
                                event_type='role_changed',
                                event_data={
                                    'target_user': user['id'],
                                    'target_email': user.get('email'),
                                    'old_role': current_role,
                                    'new_role': new_role
                                }
                            )
                            st.success(f"✅ Updated {user.get('name')} to {new_role}")
                            st.rerun()
                        else:
                            st.error("Failed to update role")
                
                # Deactivate/Activate
                st.markdown("---")
                if is_active:
                    if st.button("🔴 Deactivate User", key=f"deactivate_{user['id']}", disabled=is_current_user):
                        if db_manager.deactivate_user(user['id']):
                            db_manager.log_event(
                                user_id=current_user['id'],
                                event_type='user_deactivated',
                                event_data={
                                    'target_user': user['id'],
                                    'target_email': user.get('email')
                                }
                            )
                            st.success(f"✅ Deactivated {user.get('name')}")
                            st.rerun()
                else:
                    if st.button("🟢 Activate User", key=f"activate_{user['id']}"):
                        # Reactivate by updating is_active
                        try:
                            from firebase_admin import db
                            users_ref = db.reference('users')
                            users_ref.child(user['id']).update({'is_active': True})
                            
                            db_manager.log_event(
                                user_id=current_user['id'],
                                event_type='user_activated',
                                event_data={
                                    'target_user': user['id'],
                                    'target_email': user.get('email')
                                }
                            )
                            st.success(f"✅ Activated {user.get('name')}")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed to activate: {str(e)}")
                
                # Warning for current user
                if is_current_user:
                    st.caption("⚠️ Cannot modify your own account")
    
    @staticmethod
    def _render_role_management(db_manager):
        """Render role management and permissions"""
        st.markdown("### 🎭 Role Management & Permissions")
        
        # Get role manager
        role_manager = st.session_state.get('role_manager')
        if not role_manager:
            st.error("Role manager not available")
            return
        
        # Display roles
        for role_name, role_info in role_manager.ROLES.items():
            with st.expander(f"**{role_name.upper()}** - {role_info.get('description', '')}"):
                st.markdown(f"**Description:** {role_info.get('description', 'N/A')}")
                
                permissions = role_info.get('permissions', [])
                if '*' in permissions:
                    st.success("✅ **ALL PERMISSIONS** (Full Access)")
                else:
                    st.markdown("**Permissions:**")
                    for perm in permissions:
                        st.markdown(f"- ✅ `{perm}`")
                
                # Show user count for this role
                try:
                    users = db_manager.get_all_users(active_only=False)
                    role_users = [u for u in users if u.get('role') == role_name]
                    st.info(f"👥 **{len(role_users)}** users with this role")
                except:
                    pass
    
    @staticmethod
    def _render_analytics(db_manager):
        """Render analytics and statistics"""
        st.markdown("### 📊 Platform Analytics")
        
        try:
            # Get statistics
            stats = db_manager.get_user_stats()
            
            # Display metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Users", stats.get('total_users', 0))
            with col2:
                st.metric("Active Users", stats.get('active_users', 0))
            with col3:
                st.metric("Inactive Users", stats.get('inactive_users', 0))
            with col4:
                active_rate = 0
                if stats.get('total_users', 0) > 0:
                    active_rate = round((stats.get('active_users', 0) / stats.get('total_users', 1)) * 100, 1)
                st.metric("Active Rate", f"{active_rate}%")
            
            st.markdown("---")
            
            # Users by role
            st.markdown("#### 👥 Users by Role")
            roles_data = stats.get('users_by_role', {})
            
            if roles_data:
                # Create dataframe for chart
                df_roles = pd.DataFrame([
                    {'Role': role.title(), 'Count': count}
                    for role, count in roles_data.items()
                ])
                
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.bar_chart(df_roles.set_index('Role'))
                with col2:
                    st.dataframe(df_roles, hide_index=True, use_container_width=True)
            else:
                st.info("No user data available")
            
            st.markdown("---")
            
            # Recent activity
            st.markdown("#### 📈 Recent Activity")
            
            # Get recent users
            all_users = db_manager.get_all_users(active_only=False)
            
            # Sort by last login
            recent_users = sorted(
                [u for u in all_users if u.get('last_login')],
                key=lambda x: x.get('last_login', ''),
                reverse=True
            )[:10]
            
            if recent_users:
                df_recent = pd.DataFrame([
                    {
                        'Name': u.get('name', 'Unknown'),
                        'Email': u.get('email', 'N/A'),
                        'Role': u.get('role', 'viewer').title(),
                        'Last Login': u.get('last_login', 'Never')[:16] if u.get('last_login') else 'Never'
                    }
                    for u in recent_users
                ])
                st.dataframe(df_recent, hide_index=True, use_container_width=True)
            else:
                st.info("No recent activity")
                
        except Exception as e:
            st.error(f"Failed to load analytics: {str(e)}")
    
    @staticmethod
    def _render_audit_logs(db_manager):
        """Render audit logs"""
        st.markdown("### 📜 Audit Logs")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            event_type_filter = st.selectbox(
                "Event Type",
                ["All", "login", "logout", "role_changed", "user_deactivated", "user_activated", "page_access"]
            )
        with col2:
            limit = st.number_input("Show entries", min_value=10, max_value=1000, value=50, step=10)
        with col3:
            st.markdown("&nbsp;")
            if st.button("🔄 Refresh Logs"):
                st.rerun()
        
        try:
            # Get logs
            event_filter = None if event_type_filter == "All" else event_type_filter
            logs = db_manager.get_audit_logs(event_type=event_filter, limit=limit)
            
            if logs:
                st.info(f"📊 Showing {len(logs)} log entries")
                
                # Display logs
                for log in logs:
                    timestamp = log.get('timestamp', 'Unknown')[:19] if log.get('timestamp') else 'Unknown'
                    event_type = log.get('event_type', 'unknown')
                    user_id = log.get('user_id', 'Unknown')[:20]
                    event_data = log.get('event_data', {})
                    
                    # Color code by event type
                    if event_type == 'login':
                        icon = "🟢"
                    elif event_type == 'logout':
                        icon = "🔵"
                    elif event_type in ['role_changed', 'user_deactivated', 'user_activated']:
                        icon = "🟡"
                    else:
                        icon = "⚪"
                    
                    with st.expander(f"{icon} **{event_type}** - {timestamp} - User: {user_id}..."):
                        st.json(event_data)
            else:
                st.info("No audit logs found")
                
        except Exception as e:
            st.error(f"Failed to load audit logs: {str(e)}")
    
    @staticmethod
    def _render_settings(db_manager, current_user):
        """Render platform settings"""
        st.markdown("### ⚙️ Platform Settings")
        
        st.markdown("#### 🗑️ Database Maintenance")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### Clean Old Audit Logs")
            days = st.number_input("Delete logs older than (days)", min_value=7, max_value=365, value=90)
            
            if st.button("🗑️ Clean Old Logs"):
                with st.spinner("Cleaning logs..."):
                    try:
                        deleted = db_manager.cleanup_old_logs(days=days)
                        st.success(f"✅ Deleted {deleted} old log entries")
                        
                        # Log this action
                        db_manager.log_event(
                            user_id=current_user['id'],
                            event_type='logs_cleaned',
                            event_data={'days': days, 'deleted_count': deleted}
                        )
                    except Exception as e:
                        st.error(f"Failed to clean logs: {str(e)}")
        
        with col2:
            st.markdown("##### Export User Data")
            st.caption("Export all user data to CSV")
            
            if st.button("📥 Export Users"):
                try:
                    users = db_manager.get_all_users(active_only=False)
                    df = pd.DataFrame(users)
                    
                    csv = df.to_csv(index=False)
                    st.download_button(
                        label="💾 Download CSV",
                        data=csv,
                        file_name=f"cloudidp_users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                except Exception as e:
                    st.error(f"Failed to export: {str(e)}")
        
        st.markdown("---")
        
        # Database info
        st.markdown("#### 📊 Database Information")
        
        try:
            users = db_manager.get_all_users(active_only=False)
            logs = db_manager.get_audit_logs(limit=1000)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Users", len(users))
            with col2:
                st.metric("Audit Log Entries", len(logs))
            with col3:
                # Estimate size (rough)
                estimated_size = (len(users) * 0.5) + (len(logs) * 0.3)  # KB
                st.metric("Estimated Size", f"~{estimated_size:.1f} KB")
        except:
            st.info("Database information unavailable")
        
        st.markdown("---")
        
        # Admin actions
        st.markdown("#### 👨‍💼 Admin Information")
        st.info(f"""
        **Current Admin:** {current_user.get('name')}  
        **Email:** {current_user.get('email')}  
        **User ID:** `{current_user.get('id')}`  
        **Session:** Active  
        """)

# For backward compatibility with navigation
def render():
    """Entry point for navigation"""
    AdminPanelModule.render()