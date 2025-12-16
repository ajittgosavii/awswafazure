"""
Interactive Dashboard Module
Creates interactive visualizations using Plotly for WAF Scanner
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import streamlit as st


class InteractiveDashboard:
    """Generate interactive dashboards for WAF scan results"""
    
    def __init__(self):
        self.color_scheme = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'security': '#e74c3c',
            'reliability': '#3498db',
            'performance': '#9b59b6',
            'cost_optimization': '#2ecc71',
            'operational_excellence': '#f39c12',
            'sustainability': '#16a085'
        }
    
    def create_severity_distribution_pie(self, findings: List[Dict]) -> go.Figure:
        """Create pie chart for finding severity distribution"""
        
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM').title()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            marker=dict(colors=[
                self.color_scheme['critical'],
                self.color_scheme['high'],
                self.color_scheme['medium'],
                self.color_scheme['low']
            ]),
            hole=0.4,
            textinfo='label+value+percent',
            textfont=dict(size=14),
            hovertemplate='<b>%{label}</b><br>' +
                         'Count: %{value}<br>' +
                         'Percentage: %{percent}<br>' +
                         '<extra></extra>'
        )])
        
        fig.update_layout(
            title={
                'text': '🎯 Finding Distribution by Severity',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'family': 'Arial Black'}
            },
            height=400,
            showlegend=True,
            legend=dict(
                orientation="v",
                yanchor="middle",
                y=0.5,
                xanchor="left",
                x=1.02
            )
        )
        
        return fig
    
    def create_waf_pillar_radar(self, pillar_scores: Dict) -> go.Figure:
        """Create radar chart for WAF pillar scores"""
        
        pillars = list(pillar_scores.keys())
        scores = [pillar_scores[p].get('score', 0) for p in pillars]
        
        # Add first point again to close the radar
        pillars_closed = pillars + [pillars[0]]
        scores_closed = scores + [scores[0]]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatterpolar(
            r=scores_closed,
            theta=pillars_closed,
            fill='toself',
            fillcolor='rgba(52, 152, 219, 0.3)',
            line=dict(color='rgb(52, 152, 219)', width=2),
            marker=dict(size=8),
            name='Current Score',
            hovertemplate='<b>%{theta}</b><br>' +
                         'Score: %{r:.1f}/100<br>' +
                         '<extra></extra>'
        ))
        
        # Add target line at 80 (good score)
        fig.add_trace(go.Scatterpolar(
            r=[80] * len(pillars_closed),
            theta=pillars_closed,
            line=dict(color='rgba(46, 204, 113, 0.5)', width=2, dash='dash'),
            name='Target (80)',
            hoverinfo='skip'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100],
                    tickfont=dict(size=12),
                    gridcolor='rgba(0,0,0,0.1)'
                ),
                angularaxis=dict(
                    tickfont=dict(size=12)
                )
            ),
            title={
                'text': '🏛️ Well-Architected Framework Pillar Scores',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'family': 'Arial Black'}
            },
            height=500,
            showlegend=True
        )
        
        return fig
    
    def create_trend_chart(self, trend_data: pd.DataFrame) -> go.Figure:
        """Create line chart showing trends over time"""
        
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Total Findings Over Time', 'WAF Score Trend'),
            vertical_spacing=0.12,
            row_heights=[0.5, 0.5]
        )
        
        # Findings trend
        fig.add_trace(
            go.Scatter(
                x=trend_data['scan_date'],
                y=trend_data['total_findings'],
                mode='lines+markers',
                name='Total Findings',
                line=dict(color='#3498db', width=3),
                marker=dict(size=8),
                fill='tozeroy',
                fillcolor='rgba(52, 152, 219, 0.2)',
                hovertemplate='<b>Date:</b> %{x}<br>' +
                             '<b>Findings:</b> %{y}<br>' +
                             '<extra></extra>'
            ),
            row=1, col=1
        )
        
        # Add severity breakdown
        for severity, color in [('critical_count', '#dc3545'), 
                               ('high_count', '#fd7e14'),
                               ('medium_count', '#ffc107')]:
            if severity in trend_data.columns:
                fig.add_trace(
                    go.Scatter(
                        x=trend_data['scan_date'],
                        y=trend_data[severity],
                        mode='lines',
                        name=severity.replace('_count', '').title(),
                        line=dict(color=color, width=2, dash='dot'),
                        hovertemplate='<b>Date:</b> %{x}<br>' +
                                     '<b>Count:</b> %{y}<br>' +
                                     '<extra></extra>'
                    ),
                    row=1, col=1
                )
        
        # WAF score trend
        fig.add_trace(
            go.Scatter(
                x=trend_data['scan_date'],
                y=trend_data['overall_waf_score'],
                mode='lines+markers',
                name='WAF Score',
                line=dict(color='#2ecc71', width=3),
                marker=dict(size=8),
                fill='tozeroy',
                fillcolor='rgba(46, 204, 113, 0.2)',
                hovertemplate='<b>Date:</b> %{x}<br>' +
                             '<b>Score:</b> %{y:.1f}/100<br>' +
                             '<extra></extra>'
            ),
            row=2, col=1
        )
        
        # Add target line
        fig.add_hline(
            y=80, line_dash="dash", line_color="gray",
            annotation_text="Target", annotation_position="right",
            row=2, col=1
        )
        
        fig.update_xaxes(title_text="Scan Date", row=2, col=1)
        fig.update_yaxes(title_text="Number of Findings", row=1, col=1)
        fig.update_yaxes(title_text="Score", row=2, col=1, range=[0, 100])
        
        fig.update_layout(
            height=700,
            title={
                'text': '📈 Security Posture Trends (Last 30 Days)',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'family': 'Arial Black'}
            },
            hovermode='x unified',
            showlegend=True
        )
        
        return fig
    
    def create_service_breakdown_bar(self, findings: List[Dict]) -> go.Figure:
        """Create bar chart for findings by service"""
        
        service_counts = {}
        for finding in findings:
            service = finding.get('service', 'Unknown')
            if service not in service_counts:
                service_counts[service] = {
                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0
                }
            
            severity = finding.get('severity', 'MEDIUM').lower()
            if severity in service_counts[service]:
                service_counts[service][severity] += 1
        
        # Sort by total findings
        sorted_services = sorted(
            service_counts.items(),
            key=lambda x: sum(x[1].values()),
            reverse=True
        )[:15]  # Top 15 services
        
        services = [s[0] for s in sorted_services]
        
        fig = go.Figure()
        
        for severity, color in [('critical', '#dc3545'), ('high', '#fd7e14'),
                               ('medium', '#ffc107'), ('low', '#28a745')]:
            counts = [service_counts[s][severity] for s in services]
            fig.add_trace(go.Bar(
                name=severity.title(),
                x=services,
                y=counts,
                marker_color=color,
                hovertemplate='<b>%{x}</b><br>' +
                             f'<b>{severity.title()}:</b> %{{y}}<br>' +
                             '<extra></extra>'
            ))
        
        fig.update_layout(
            barmode='stack',
            title={
                'text': '🔧 Findings by AWS Service',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'family': 'Arial Black'}
            },
            xaxis_title="AWS Service",
            yaxis_title="Number of Findings",
            height=500,
            hovermode='x unified',
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        return fig
    
    def create_cost_impact_waterfall(self, cost_data: Dict) -> go.Figure:
        """Create waterfall chart for cost impact"""
        
        categories = []
        values = []
        measures = []
        
        # Monthly waste by service
        for service, data in cost_data.get('by_service', {}).items():
            if data['waste'] > 0:
                categories.append(f"{service} Waste")
                values.append(data['waste'])
                measures.append('relative')
        
        # Risk exposure
        if cost_data.get('total_risk_exposure', 0) > 0:
            categories.append('Security Risk')
            values.append(cost_data['total_risk_exposure'] / 12)  # Monthly equivalent
            measures.append('relative')
        
        # Total
        categories.append('Total Monthly Impact')
        values.append(0)
        measures.append('total')
        
        fig = go.Figure(go.Waterfall(
            name="Cost Impact",
            orientation="v",
            measure=measures,
            x=categories,
            textposition="outside",
            text=[f"${v:,.0f}" for v in values],
            y=values,
            connector={"line": {"color": "rgb(63, 63, 63)"}},
            increasing={"marker": {"color": "#dc3545"}},
            decreasing={"marker": {"color": "#28a745"}},
            totals={"marker": {"color": "#3498db"}}
        ))
        
        fig.update_layout(
            title={
                'text': '💰 Monthly Cost Impact Breakdown',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'family': 'Arial Black'}
            },
            yaxis_title="Monthly Cost (USD)",
            height=500,
            showlegend=False
        )
        
        return fig
    
    def create_compliance_heatmap(self, compliance_report: Dict) -> go.Figure:
        """Create heatmap for compliance violations"""
        
        frameworks = []
        severities = ['Critical', 'High', 'Medium', 'Low']
        data = []
        
        for framework, violations in compliance_report.get('frameworks', {}).items():
            frameworks.append(framework)
            row = [
                violations.get('critical', 0),
                violations.get('high', 0),
                violations.get('medium', 0),
                violations.get('low', 0)
            ]
            data.append(row)
        
        # Transpose for correct orientation
        data_transposed = list(map(list, zip(*data)))
        
        fig = go.Figure(data=go.Heatmap(
            z=data_transposed,
            x=frameworks,
            y=severities,
            colorscale=[
                [0, '#d4edda'],      # Light green for 0
                [0.25, '#fff3cd'],   # Light yellow
                [0.5, '#f8d7da'],    # Light red
                [1, '#dc3545']       # Dark red for high
            ],
            text=data_transposed,
            texttemplate='%{text}',
            textfont={"size": 16},
            hoverontemplate='<b>%{y} Severity</b><br>' +
                           '<b>%{x}</b><br>' +
                           'Violations: %{z}<br>' +
                           '<extra></extra>'
        ))
        
        fig.update_layout(
            title={
                'text': '📋 Compliance Framework Violations Heatmap',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'family': 'Arial Black'}
            },
            xaxis_title="Compliance Framework",
            yaxis_title="Severity",
            height=400
        )
        
        return fig
    
    def create_finding_age_histogram(self, age_data: pd.DataFrame) -> go.Figure:
        """Create histogram for finding ages"""
        
        fig = px.histogram(
            age_data,
            x='age_days',
            nbins=30,
            color='severity',
            color_discrete_map={
                'CRITICAL': self.color_scheme['critical'],
                'HIGH': self.color_scheme['high'],
                'MEDIUM': self.color_scheme['medium'],
                'LOW': self.color_scheme['low']
            },
            title='⏳ Finding Age Distribution',
            labels={'age_days': 'Age (Days)', 'count': 'Number of Findings'}
        )
        
        # Add vertical lines for age thresholds
        fig.add_vline(x=7, line_dash="dash", line_color="orange", 
                     annotation_text="1 Week", annotation_position="top")
        fig.add_vline(x=30, line_dash="dash", line_color="red",
                     annotation_text="1 Month", annotation_position="top")
        fig.add_vline(x=90, line_dash="dash", line_color="darkred",
                     annotation_text="3 Months", annotation_position="top")
        
        fig.update_layout(
            height=400,
            title={
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'family': 'Arial Black'}
            }
        )
        
        return fig
    
    def create_dashboard_summary(self, scan_result: Dict, historical_data: Optional[pd.DataFrame] = None) -> None:
        """Create comprehensive Streamlit dashboard"""
        
        st.title("🔐 AWS Well-Architected Framework Dashboard")
        
        # Key Metrics Row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="Total Findings",
                value=scan_result.get('total_findings', 0),
                delta=self._calculate_delta(historical_data, 'total_findings') if historical_data is not None else None,
                delta_color="inverse"
            )
        
        with col2:
            st.metric(
                label="WAF Score",
                value=f"{scan_result.get('overall_waf_score', 0):.1f}/100",
                delta=self._calculate_delta(historical_data, 'overall_waf_score') if historical_data is not None else None,
                delta_color="normal"
            )
        
        with col3:
            critical = scan_result.get('critical_count', 0)
            st.metric(
                label="Critical Issues",
                value=critical,
                delta=self._calculate_delta(historical_data, 'critical_count') if historical_data is not None else None,
                delta_color="inverse"
            )
        
        with col4:
            cost_impact = scan_result.get('cost_impact', {})
            monthly_waste = cost_impact.get('total_monthly_waste', 0)
            st.metric(
                label="Monthly Waste",
                value=f"${monthly_waste:,.0f}",
                delta=None
            )
        
        # Charts Row 1
        col1, col2 = st.columns(2)
        
        with col1:
            st.plotly_chart(
                self.create_severity_distribution_pie(scan_result.get('findings', [])),
                use_container_width=True
            )
        
        with col2:
            st.plotly_chart(
                self.create_waf_pillar_radar(scan_result.get('pillar_distribution', {})),
                use_container_width=True
            )
        
        # Trend Chart (if historical data available)
        if historical_data is not None and len(historical_data) > 1:
            st.plotly_chart(
                self.create_trend_chart(historical_data),
                use_container_width=True
            )
        
        # Charts Row 2
        st.plotly_chart(
            self.create_service_breakdown_bar(scan_result.get('findings', [])),
            use_container_width=True
        )
        
        # Compliance and Cost
        if scan_result.get('compliance_report'):
            col1, col2 = st.columns(2)
            
            with col1:
                st.plotly_chart(
                    self.create_compliance_heatmap(scan_result['compliance_report']),
                    use_container_width=True
                )
            
            with col2:
                if scan_result.get('cost_impact'):
                    st.plotly_chart(
                        self.create_cost_impact_waterfall(scan_result['cost_impact']),
                        use_container_width=True
                    )
    
    def _calculate_delta(self, df: pd.DataFrame, column: str) -> Optional[float]:
        """Calculate change from previous scan"""
        if df is None or len(df) < 2:
            return None
        
        current = df.iloc[-1][column]
        previous = df.iloc[-2][column]
        
        return current - previous


# Example usage
if __name__ == "__main__":
    dashboard = InteractiveDashboard()
    
    # Test data
    findings = [
        {'severity': 'CRITICAL', 'service': 'S3'},
        {'severity': 'HIGH', 'service': 'EC2'},
        {'severity': 'MEDIUM', 'service': 'RDS'},
    ]
    
    fig = dashboard.create_severity_distribution_pie(findings)
    fig.show()
