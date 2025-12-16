"""
AWS Theme Styling - COMPLETE OVERHAUL
Hybrid theme: Dark interface with LIGHT metric cards for guaranteed visibility
"""

import streamlit as st

class AWSTheme:
    """AWS-themed styling for CloudIDP - VISIBILITY GUARANTEED"""
    
    # AWS Brand Colors
    AWS_ORANGE = "#FF9900"
    AWS_DARK = "#232F3E"
    AWS_DARK_GRAY = "#161E2D"
    AWS_LIGHT_GRAY = "#F2F3F4"
    AWS_GRAY = "#545B64"
    AWS_WHITE = "#FFFFFF"
    AWS_BLUE = "#0073BB"
    AWS_SUCCESS = "#00A86B"
    AWS_WARNING = "#FFB81C"
    AWS_ERROR = "#D13212"
    
    @staticmethod
    def apply_aws_theme():
        """Apply AWS console-style hybrid theme - Dark background, Light metrics"""
        
        st.markdown("""
        <style>
            /* ===== AWS HYBRID THEME - GUARANTEED VISIBILITY ===== */
            
            /* Main app background - DARK */
            .stApp {
                background-color: #232F3E;
            }
            
            .main .block-container {
                padding-top: 2rem;
                padding-bottom: 2rem;
                background-color: #232F3E;
                max-width: 1400px;
            }
            
            /* ===== HEADERS ===== */
            
            h1 {
                color: #FF9900 !important;
                font-family: 'Amazon Ember', 'Helvetica Neue', Roboto, Arial, sans-serif !important;
                font-weight: 700 !important;
                padding: 1rem 0;
                border-bottom: 3px solid #FF9900;
                margin-bottom: 1.5rem;
            }
            
            h2 {
                color: #FF9900 !important;
                font-family: 'Amazon Ember', 'Helvetica Neue', Roboto, Arial, sans-serif !important;
                font-weight: 600 !important;
                margin-top: 1.5rem;
            }
            
            h3 {
                color: #FFFFFF !important;
                font-family: 'Amazon Ember', 'Helvetica Neue', Roboto, Arial, sans-serif !important;
                font-weight: 500 !important;
            }
            
            /* ===== SIDEBAR ===== */
            
            [data-testid="stSidebar"] {
                background-color: #161E2D !important;
                border-right: 2px solid #FF9900;
            }
            
            [data-testid="stSidebar"] * {
                color: #FFFFFF !important;
            }
            
            [data-testid="stSidebar"] h1,
            [data-testid="stSidebar"] h2,
            [data-testid="stSidebar"] h3 {
                color: #FF9900 !important;
                border-bottom: 1px solid #FF9900;
                padding-bottom: 0.5rem;
            }
            
            /* ===== TABS ===== */
            
            .stTabs [data-baseweb="tab-list"] {
                gap: 0px;
                background-color: #161E2D;
                border-bottom: 2px solid #FF9900;
                padding: 0;
            }
            
            .stTabs [data-baseweb="tab"] {
                height: 50px;
                background-color: #232F3E;
                border: 1px solid #444444;
                border-bottom: none;
                color: #FFFFFF;
                font-weight: 600;
                font-size: 14px;
                padding: 0 1.5rem;
                margin: 0;
                border-radius: 4px 4px 0 0;
            }
            
            .stTabs [data-baseweb="tab"][aria-selected="true"] {
                background-color: #FF9900 !important;
                color: #232F3E !important;
                border-bottom: 2px solid #FF9900;
            }
            
            .stTabs [data-baseweb="tab"]:hover {
                background-color: #FF9900;
                color: #232F3E;
            }
            
            .stTabs [data-baseweb="tab-panel"] {
                background-color: #232F3E;
                padding: 1.5rem;
                border: 1px solid #444444;
                border-top: none;
                border-radius: 0 0 4px 4px;
            }
            
            /* ===== BUTTONS ===== */
            
            .stButton > button {
                background-color: #FF9900 !important;
                color: #232F3E !important;
                border: none !important;
                border-radius: 4px !important;
                padding: 0.5rem 1.5rem !important;
                font-weight: 600 !important;
                font-size: 14px !important;
                transition: all 0.3s ease !important;
            }
            
            .stButton > button:hover {
                background-color: #EC7211 !important;
                box-shadow: 0 4px 8px rgba(255, 153, 0, 0.3) !important;
                transform: translateY(-1px);
            }
            
            /* ===== DATAFRAMES/TABLES ===== */
            
            .dataframe {
                background-color: #FFFFFF !important;
                color: #232F3E !important;
                border: 1px solid #FF9900 !important;
            }
            
            .dataframe thead tr th {
                background-color: #FF9900 !important;
                color: #232F3E !important;
                font-weight: 700 !important;
                padding: 12px !important;
                border: none !important;
            }
            
            .dataframe tbody tr {
                background-color: #FFFFFF !important;
                border-bottom: 1px solid #E0E0E0 !important;
            }
            
            .dataframe tbody tr:hover {
                background-color: #F8F9FA !important;
            }
            
            .dataframe tbody tr td {
                color: #232F3E !important;
                padding: 10px !important;
            }
            
            /* ===== INPUT FIELDS ===== */
            
            .stTextInput > div > div > input,
            .stTextArea > div > div > textarea,
            .stNumberInput > div > div > input {
                background-color: #FFFFFF !important;
                color: #232F3E !important;
                border: 2px solid #545B64 !important;
                border-radius: 4px !important;
            }
            
            .stTextInput > div > div > input:focus,
            .stTextArea > div > div > textarea:focus,
            .stNumberInput > div > div > input:focus {
                border-color: #FF9900 !important;
                box-shadow: 0 0 0 2px rgba(255, 153, 0, 0.2) !important;
            }
            
            /* ===== SELECTBOX/DROPDOWNS - WHITE BACKGROUND ===== */
            
            .stSelectbox > div > div {
                background-color: #FFFFFF !important;
                color: #232F3E !important;
                border: 2px solid #545B64 !important;
                border-radius: 4px !important;
            }
            
            .stSelectbox > div > div:hover {
                border-color: #FF9900 !important;
            }
            
            /* Dropdown menu options */
            div[data-baseweb="select"] > div {
                background-color: #FFFFFF !important;
                color: #232F3E !important;
            }
            
            [role="listbox"] {
                background-color: #FFFFFF !important;
            }
            
            [role="option"] {
                background-color: #FFFFFF !important;
                color: #232F3E !important;
            }
            
            [role="option"]:hover {
                background-color: #F8F9FA !important;
            }
            
            /* ===== ALERTS ===== */
            
            .stSuccess {
                background-color: rgba(0, 168, 107, 0.1) !important;
                border-left: 4px solid #00A86B !important;
                color: #FFFFFF !important;
                padding: 1rem !important;
            }
            
            .stWarning {
                background-color: rgba(255, 184, 28, 0.1) !important;
                border-left: 4px solid #FFB81C !important;
                color: #FFFFFF !important;
                padding: 1rem !important;
            }
            
            .stError {
                background-color: rgba(209, 50, 18, 0.1) !important;
                border-left: 4px solid #D13212 !important;
                color: #FFFFFF !important;
                padding: 1rem !important;
            }
            
            .stInfo {
                background-color: rgba(0, 115, 187, 0.1) !important;
                border-left: 4px solid #0073BB !important;
                color: #FFFFFF !important;
                padding: 1rem !important;
            }
            
            /* ===== EXPANDERS ===== */
            
            .streamlit-expanderHeader {
                background-color: #161E2D !important;
                color: #FF9900 !important;
                border: 1px solid #FF9900 !important;
                border-radius: 4px !important;
                font-weight: 600 !important;
            }
            
            .streamlit-expanderHeader:hover {
                background-color: #232F3E !important;
            }
            
            .streamlit-expanderContent {
                background-color: #232F3E !important;
                border: 1px solid #444444 !important;
                border-top: none !important;
                color: #FFFFFF !important;
            }
            
            /* ===== PROGRESS BARS ===== */
            
            .stProgress > div > div > div {
                background-color: #FF9900 !important;
            }
            
            /* ===== CHARTS ===== */
            
            [data-testid="stPlotlyChart"] {
                background-color: #FFFFFF !important;
                border: 1px solid #E0E0E0 !important;
                border-radius: 8px !important;
                padding: 1rem !important;
            }
            
            /* ===== DIVIDERS ===== */
            
            hr {
                border-color: #FF9900 !important;
                opacity: 0.5 !important;
            }
            
            /* ===== SCROLLBAR ===== */
            
            ::-webkit-scrollbar {
                width: 10px;
                height: 10px;
            }
            
            ::-webkit-scrollbar-track {
                background: #161E2D;
            }
            
            ::-webkit-scrollbar-thumb {
                background: #FF9900;
                border-radius: 5px;
            }
            
            ::-webkit-scrollbar-thumb:hover {
                background: #EC7211;
            }
            
            /* ===== RADIO & CHECKBOXES ===== */
            
            .stRadio > div {
                background-color: #161E2D;
                padding: 0.5rem;
                border-radius: 4px;
            }
            
            .stRadio label {
                color: #FFFFFF !important;
            }
            
            .stCheckbox {
                color: #FFFFFF !important;
            }
            
            /* ===== GENERAL TEXT ===== */
            
            p, span, label, li {
                color: #FFFFFF !important;
            }
            
            .stMarkdown {
                color: #FFFFFF !important;
            }
            
            .stCaption {
                color: #F2F3F4 !important;
            }
            
            /* ===== CHAT MESSAGES ===== */
            
            .stChatMessage {
                background-color: #161E2D !important;
                border: 1px solid #444444 !important;
                border-radius: 8px !important;
            }
            
            /* ===== FOOTER ===== */
            
            footer {
                background-color: #161E2D !important;
                border-top: 2px solid #FF9900 !important;
            }
            
            footer p {
                color: #F2F3F4 !important;
            }
        </style>
        """, unsafe_allow_html=True)
    
    @staticmethod
    def aws_header(title: str, subtitle: str = None):
        """Create AWS-styled header banner"""
        subtitle_html = f'<p style="color: #F2F3F4 !important; margin: 0.5rem 0 0 0 !important; font-size: 1.1rem !important;">{subtitle}</p>' if subtitle else ''
        
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #232F3E 0%, #FF9900 100%); padding: 2rem; border-radius: 8px; margin-bottom: 2rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3); border: 1px solid #FF9900;">
            <h1 style="color: #FFFFFF !important; margin: 0 !important; padding: 0 !important; border: none !important;">☁️ {title}</h1>
            {subtitle_html}
        </div>
        """, unsafe_allow_html=True)
    
    @staticmethod
    def aws_service_card(title: str, content: str, icon: str = "📦"):
        """Create AWS-styled service card"""
        st.markdown(f"""
        <div style="background-color: #161E2D; border: 2px solid #FF9900; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3); transition: all 0.3s ease;">
            <h3 style="color: #FFFFFF !important;">{icon} {title}</h3>
            <p style="color: #F2F3F4 !important;">{content}</p>
        </div>
        """, unsafe_allow_html=True)
    
    @staticmethod
    def aws_badge(text: str, badge_type: str = "info"):
        """Create AWS-styled status badge"""
        colors = {
            "success": {"bg": "#00A86B", "text": "#FFFFFF"},
            "warning": {"bg": "#FFB81C", "text": "#232F3E"},
            "error": {"bg": "#D13212", "text": "#FFFFFF"},
            "info": {"bg": "#0073BB", "text": "#FFFFFF"}
        }
        color = colors.get(badge_type, colors["info"])
        return f'<span style="display: inline-block; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 600; font-size: 0.875rem; margin: 0.25rem; background-color: {color["bg"]}; color: {color["text"]};">{text}</span>'
    
    @staticmethod
    def aws_metric_card(label: str, value: str, delta: str = None, icon: str = "📊"):
        """
        Create AWS-styled metric card with LIGHT BACKGROUND
        GUARANTEED VISIBILITY - White card with dark text
        """
        delta_html = f'<div style="color: #00A86B !important; margin-top: 0.5rem; font-size: 14px; font-weight: 600;">{delta}</div>' if delta else ''
        
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #FFFFFF 0%, #F8F9FA 100%);
            border: 2px solid #FF9900;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 12px rgba(255, 153, 0, 0.2);
            min-height: 140px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            transition: all 0.3s ease;
        ">
            <div style="
                color: #000000 !important;
                font-weight: 700;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 12px;
                font-family: 'Amazon Ember', 'Helvetica Neue', Roboto, Arial, sans-serif;
            ">
                <span style="font-size: 20px; margin-right: 8px;">{icon}</span>
                {label}
            </div>
            <div style="
                color: #000000 !important;
                font-weight: 900;
                font-size: 48px;
                line-height: 1;
                font-family: 'Amazon Ember', 'Helvetica Neue', Roboto, Arial, sans-serif;
            ">
                {value}
            </div>
            {delta_html}
        </div>
        """, unsafe_allow_html=True)