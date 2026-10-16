import streamlit as st

def html(content):
    """Render a small HTML fragment without Markdown code-block interpretation."""
    st.html(content)

def page_header(title, description, badge="DATABASE MONITORING"):
    html(f"""
    <div class="topbar">
        <div class="topbar-left">
            <div class="page-heading">{title}</div>
            <div class="page-description">{description}</div>
        </div>
        <div class="topbar-right">
            <div class="live-pill">
                <div class="live-dot"></div>
                {badge}
            </div>
        </div>
    </div>
    """)

def panel_header(title, subtitle=""):
    html(f"""
    <div class="panel">
        <div class="panel-header">
            <div>
                <div class="panel-title">{title}</div>
                <div class="panel-subtitle">{subtitle}</div>
            </div>
        </div>
    </div>
    """)
