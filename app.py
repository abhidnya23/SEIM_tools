import streamlit as st

from components.sidebar import show_sidebar
from pages.dashboard import show_dashboard
from pages.logs import show_logs
from pages.alerts import show_alerts
from pages.analysis import show_analysis
from pages.reports import show_reports

st.set_page_config(
    page_title="Sentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

def load_css():
    try:
        with open("assets/style.css", "r", encoding="utf-8") as file:
            st.markdown(f"<style>{file.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.warning("CSS file not found: assets/style.css")

load_css()
page = show_sidebar()

if page == "Dashboard":
    show_dashboard()
elif page == "Log Explorer":
    show_logs()
elif page == "Security Alerts":
    show_alerts()
elif page == "Threat Analysis":
    show_analysis()
elif page == "Security Reports":
    show_reports()
else:
    show_dashboard()
