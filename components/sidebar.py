import streamlit as st
from components.ui import html
from database import get_log_count, get_alert_count

NAV_ITEMS = [
    ("Dashboard", "📊"),
    ("Log Explorer", "📁"),
    ("Security Alerts", "🚨"),
    ("Threat Analysis", "🔍"),
    ("Security Reports", "📄"),
]

def show_sidebar():
    if "page" not in st.session_state:
        st.session_state.page = "Dashboard"

    with st.sidebar:
        html("""
        <div class="brand">
            <div class="brand-shield">🛡️</div>
            <div class="brand-name">SENTINEL</div>
        </div>
        <div class="brand-subtitle">SECURITY OPERATIONS CENTER</div>
        <div class="nav-section">MONITORING</div>
        """)

        for label, icon in NAV_ITEMS:

            if st.button(
                f"{icon}  {label}",
                key=f"nav_{label}",
                use_container_width=True,
                type="primary" if st.session_state.page == label else "secondary",
            ):
                st.session_state.page = label
                st.rerun()

        try:
            logs = get_log_count()
            alerts = get_alert_count()
            html(f"""
            <div class="sidebar-status">
                <div class="sidebar-status-title">DATABASE STATUS</div>
                <div class="sidebar-online">● CONNECTED</div>
                <div class="sidebar-info">{logs} logs stored</div>
                <div class="sidebar-info">{alerts} alerts generated</div>
            </div>
            """)
        except Exception:
            html("""
            <div class="sidebar-status">
                <div class="sidebar-status-title">DATABASE STATUS</div>
                <div class="sidebar-info">Unable to retrieve database counts</div>
            </div>
            """)

    return st.session_state.page
