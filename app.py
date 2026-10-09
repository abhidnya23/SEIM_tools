import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from database import (
    get_logs,
    get_alerts,
    get_log_count,
    get_alert_count,
    get_high_alert_count,
    get_critical_alert_count
)

from log_parser import (
    parse_log_file,
    save_logs_to_database
)

from detection_engine import run_detection


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Sentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# LOAD CSS
# ============================================================

def load_css():

    try:

        with open(
            "assets/style.css",
            "r",
            encoding="utf-8"
        ) as f:

            css = f.read()

        st.markdown(
            f"<style>{css}</style>",
            unsafe_allow_html=True
        )

    except FileNotFoundError:

        st.error(
            "style.css not found. "
            "Make sure assets/style.css exists."
        )


load_css()


# ============================================================
# HTML HELPER
# ============================================================

def html(content):
    """
    Render custom HTML using Streamlit's HTML renderer.
    """

    st.html(content)


# ============================================================
# SESSION STATE
# ============================================================

if "page" not in st.session_state:

    st.session_state.page = "Overview"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def load_logs():

    try:

        return get_logs()

    except Exception as e:

        st.error(
            f"Unable to load logs: {e}"
        )

        return []


def load_alerts():

    try:

        return get_alerts()

    except Exception as e:

        st.error(
            f"Unable to load alerts: {e}"
        )

        return []


def get_threat_score(
    alert_count,
    high_count,
    critical_count
):

    if alert_count == 0:

        return 0

    score = (
        alert_count
        + (high_count * 5)
        + (critical_count * 10)
    )

    return min(score, 100)


def get_threat_status(score):

    if score >= 70:

        return "HIGH"

    elif score >= 40:

        return "MEDIUM"

    else:

        return "LOW"


def severity_class(severity):

    severity = str(
        severity
    ).lower()

    if severity == "critical":

        return "sev-critical"

    elif severity == "high":

        return "sev-high"

    elif severity == "medium":

        return "sev-medium"

    return "sev-low"



def generate_pdf_report(
    logs,
    alerts,
    total_events,
    total_alerts,
    high_count,
    critical_count,
    threat_score,
    threat_status
):
    """Generate a PDF security report from the current Sentinel data."""

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        alignment=TA_CENTER,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        alignment=TA_CENTER,
        textColor=colors.grey,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=15,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "ReportNormal",
        parent=styles["Normal"],
        fontSize=9,
        leading=13
    )

    small_style = ParagraphStyle(
        "ReportSmall",
        parent=styles["Normal"],
        fontSize=7,
        leading=9
    )

    story = []

    story.append(Paragraph("SENTINEL SOC", title_style))
    story.append(Paragraph("SECURITY MONITORING REPORT", subtitle_style))
    story.append(
        Paragraph(
            "Generated: " + datetime.now().strftime("%d %B %Y, %H:%M:%S"),
            subtitle_style
        )
    )

    story.append(Paragraph("Executive Summary", heading_style))
    story.append(
        Paragraph(
            "This report provides a summary of security events and alerts "
            "detected by the Sentinel SOC monitoring platform.",
            normal_style
        )
    )
    story.append(Spacer(1, 12))

    # Security metrics
    story.append(Paragraph("Security Metrics", heading_style))

    metrics = [
        ["Metric", "Value"],
        ["Total Events", str(total_events)],
        ["Security Alerts", str(total_alerts)],
        ["High Severity Alerts", str(high_count)],
        ["Critical Alerts", str(critical_count)],
        ["Threat Score", str(threat_score)],
        ["Threat Level", str(threat_status)]
    ]

    metrics_table = Table(metrics, colWidths=[280, 180])

    metrics_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172236")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F5F7FA")),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(metrics_table)

    # Severity summary
    story.append(Paragraph("Alert Severity Summary", heading_style))

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for alert in alerts:
        severity = str(alert.get("severity", "Low")).strip().capitalize()
        if severity in severity_counts:
            severity_counts[severity] += 1

    severity_data = [["Severity", "Number of Alerts"]]

    for severity, count in severity_counts.items():
        severity_data.append([severity, str(count)])

    severity_table = Table(
        severity_data,
        colWidths=[280, 180]
    )

    severity_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172236")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(severity_table)

    # Alert details
    story.append(Paragraph("Security Alert Details", heading_style))

    display_columns = [
        "id",
        "alert_type",
        "description",
        "severity",
        "username",
        "ip_address",
        "timestamp",
        "status"
    ]

    if alerts:
        available_columns = [
            column
            for column in display_columns
            if column in alerts[0]
        ]
    else:
        available_columns = []

    if available_columns:
        table_data = [
            [
                column.replace("_", " ").title()
                for column in available_columns
            ]
        ]

        for alert in alerts:
            row = []

            for column in available_columns:
                value = alert.get(column, "")

                if value is None:
                    value = ""

                row.append(
                    Paragraph(str(value), small_style)
                )

            table_data.append(row)

        column_widths = [
            520 / len(available_columns)
        ] * len(available_columns)

        alert_table = Table(
            table_data,
            colWidths=column_widths,
            repeatRows=1
        )

        alert_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172236")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#F5F7FA")]
                )
            ])
        )

        story.append(alert_table)
    else:
        story.append(
            Paragraph(
                "No alert details available.",
                normal_style
            )
        )

    # Detection rule activity
    story.append(Paragraph("Detection Rule Activity", heading_style))

    alert_types = {}

    for alert in alerts:
        alert_type = str(alert.get("alert_type", "Unknown"))
        alert_types[alert_type] = alert_types.get(alert_type, 0) + 1

    type_data = [["Detection Rule", "Count"]]

    for alert_type, count in sorted(
        alert_types.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        type_data.append([alert_type, str(count)])

    if len(type_data) > 1:
        type_table = Table(
            type_data,
            colWidths=[360, 100]
        )

        type_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172236")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
            ])
        )

        story.append(type_table)

    # Summary
    story.append(Paragraph("Report Summary", heading_style))
    story.append(
        Paragraph(
            f"The Sentinel SOC system recorded {total_events} events and "
            f"generated {total_alerts} security alerts. The system recorded "
            f"{high_count} high-severity alerts and {critical_count} critical "
            f"alerts. The calculated threat score is {threat_score}, "
            f"classified as {threat_status}.",
            normal_style
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "SENTINEL SOC • Security Monitoring Platform • v1.0",
            subtitle_style
        )
    )

    doc.build(story)

    buffer.seek(0)

    return buffer.getvalue()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    # --------------------------------------------------------
    # BRAND
    # --------------------------------------------------------

    html("""
    <div class="brand">

        <div class="brand-shield">
            🛡️
        </div>

        <div class="brand-name">
            SENTINEL
        </div>

    </div>

    <div class="brand-subtitle">
        SECURITY OPERATIONS CENTER
    </div>
    """)


    # --------------------------------------------------------
    # MONITORING
    # --------------------------------------------------------

    html("""
    <div class="nav-section">
        MONITORING
    </div>
    """)


    # Dashboard

    if st.button(
        "📊   Dashboard",
        use_container_width=True,
        type=(
            "primary"
            if st.session_state.page == "Overview"
            else "secondary"
        )
    ):

        st.session_state.page = "Overview"

        st.rerun()


    # Log Explorer

    if st.button(
        "📁   Log Explorer",
        use_container_width=True,
        type=(
            "primary"
            if st.session_state.page == "Logs"
            else "secondary"
        )
    ):

        st.session_state.page = "Logs"

        st.rerun()


    # Security Alerts

    if st.button(
        "🚨   Security Alerts",
        use_container_width=True,
        type=(
            "primary"
            if st.session_state.page == "Alerts"
            else "secondary"
        )
    ):

        st.session_state.page = "Alerts"

        st.rerun()


    # Threat Analysis

    if st.button(
        "🔍   Threat Analysis",
        use_container_width=True,
        type=(
            "primary"
            if st.session_state.page == "Analysis"
            else "secondary"
        )
    ):

        st.session_state.page = "Analysis"

        st.rerun()


    # Security Reports

    if st.button(
        "📄   Security Reports",
        use_container_width=True,
        type=(
            "primary"
            if st.session_state.page == "Reports"
            else "secondary"
        )
    ):

        st.session_state.page = "Reports"

        st.rerun()


    # --------------------------------------------------------
    # SYSTEM
    # --------------------------------------------------------

    html("""
    <div class="nav-divider"></div>

    <div class="nav-section">
        SYSTEM
    </div>
    """)


    # Settings

    if st.button(
        "⚙️   Settings",
        use_container_width=True,
        type=(
            "primary"
            if st.session_state.page == "Settings"
            else "secondary"
        )
    ):

        st.session_state.page = "Settings"

        st.rerun()


    # --------------------------------------------------------
    # DATABASE STATUS
    # --------------------------------------------------------

    log_count = get_log_count()

    alert_count = get_alert_count()


    html(f"""
    <div class="sidebar-status">

        <div class="sidebar-status-title">
            DATABASE STATUS
        </div>

        <div class="sidebar-online">
            ● CONNECTED
        </div>

        <div class="sidebar-info">
            {log_count} logs stored
        </div>

        <div class="sidebar-info">
            {alert_count} alerts generated
        </div>

    </div>
    """)


# ============================================================
# DASHBOARD
# ============================================================

if st.session_state.page == "Overview":

    # --------------------------------------------------------
    # DATABASE DATA
    # --------------------------------------------------------

    total_events = get_log_count()

    total_alerts = get_alert_count()

    high_alerts = get_high_alert_count()

    critical_alerts = get_critical_alert_count()

    logs = load_logs()

    alerts = load_alerts()


    # --------------------------------------------------------
    # THREAT SCORE
    # --------------------------------------------------------

    threat_score = get_threat_score(
        total_alerts,
        high_alerts,
        critical_alerts
    )

    threat_status = get_threat_status(
        threat_score
    )


    if threat_status == "HIGH":

        threat_class = "threat-high"

    elif threat_status == "MEDIUM":

        threat_class = "threat-medium"

    else:

        threat_class = "threat-low"


    current_time = datetime.now().strftime(
        "%H:%M:%S"
    )


    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    html(f"""
    <div class="topbar">

        <div class="topbar-left">

            <div class="page-heading">
                Security Overview
            </div>

            <div class="page-description">
                Security monitoring and threat analysis
            </div>

        </div>

        <div class="topbar-right">

            <div class="live-pill">

                <div class="live-dot"></div>

                DATABASE MONITORING

            </div>

            <div class="panel-badge">
                {current_time}
            </div>

        </div>

    </div>
    """)


    # --------------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------------

    c1, c2, c3, c4 = st.columns(
        4,
        gap="medium"
    )


    # Total Events

    with c1:

        html(f"""
        <div class="kpi">

            <div class="kpi-top">

                <div class="kpi-title">
                    TOTAL EVENTS
                </div>

                <div class="kpi-icon">
                    📊
                </div>

            </div>

            <div class="kpi-value">
                {total_events:,}
            </div>

            <div class="kpi-bottom">

                <span class="kpi-neutral">
                    Logs stored in MySQL
                </span>

            </div>

        </div>
        """)


    # Security Alerts

    with c2:

        html(f"""
        <div class="kpi">

            <div class="kpi-top">

                <div class="kpi-title">
                    SECURITY ALERTS
                </div>

                <div class="kpi-icon">
                    🚨
                </div>

            </div>

            <div class="kpi-value">
                {total_alerts:,}
            </div>

            <div class="kpi-bottom">

                <span class="kpi-positive">
                    Detection engine
                </span>

                <span class="kpi-neutral">
                    generated
                </span>

            </div>

        </div>
        """)


    # High Severity

    with c3:

        html(f"""
        <div class="kpi">

            <div class="kpi-top">

                <div class="kpi-title">
                    HIGH SEVERITY
                </div>

                <div class="kpi-icon">
                    ⚠️
                </div>

            </div>

            <div class="kpi-value">
                {high_alerts:,}
            </div>

            <div class="kpi-bottom">

                <span class="kpi-warning">
                    High priority
                </span>

                <span class="kpi-neutral">
                    alerts
                </span>

            </div>

        </div>
        """)


    # Critical Threats

    with c4:

        html(f"""
        <div class="kpi">

            <div class="kpi-top">

                <div class="kpi-title">
                    CRITICAL THREATS
                </div>

                <div class="kpi-icon">
                    🔴
                </div>

            </div>

            <div class="kpi-value">
                {critical_alerts:,}
            </div>

            <div class="kpi-bottom">

                <span class="kpi-danger">
                    Critical
                </span>

                <span class="kpi-neutral">
                    alerts
                </span>

            </div>

        </div>
        """)


    st.write("")


    # --------------------------------------------------------
    # FAILED LOGIN CHART + THREAT SCORE
    # --------------------------------------------------------

    chart_col, score_col = st.columns(
        [2.2, 1],
        gap="medium"
    )


    # --------------------------------------------------------
    # FAILED LOGIN CHART
    # --------------------------------------------------------

    with chart_col:

        html("""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Failed Login Activity
                    </div>

                    <div class="panel-subtitle">
                        Authentication failures from stored logs
                    </div>

                </div>

                <div class="panel-badge">
                    DATABASE
                </div>

            </div>

        </div>
        """)


        if logs:

            logs_df = pd.DataFrame(logs)

            logs_df["timestamp"] = pd.to_datetime(
                logs_df["timestamp"],
                errors="coerce"
            )


            failed = logs_df[
                logs_df["status"]
                .astype(str)
                .str.lower()
                == "failed"
            ].copy()


            if not failed.empty:

                failed["hour"] = (
                    failed["timestamp"]
                    .dt.strftime("%H:00")
                )


                login_data = (
                    failed
                    .groupby("hour")
                    .size()
                    .reset_index(
                        name="Failed Logins"
                    )
                )


                login_data = login_data.sort_values(
                    "hour"
                )


                fig = go.Figure()


                fig.add_trace(
                    go.Scatter(
                        x=login_data["hour"],
                        y=login_data["Failed Logins"],

                        mode="lines+markers",

                        line=dict(
                            color="#38bdf8",
                            width=3
                        ),

                        marker=dict(
                            size=7
                        ),

                        fill="tozeroy",

                        fillcolor=(
                            "rgba(56,189,248,0.06)"
                        ),

                        hovertemplate=(
                            "<b>%{x}</b><br>"
                            "Failed logins: %{y}"
                            "<extra></extra>"
                        )
                    )
                )


                fig.update_layout(

                    height=300,

                    paper_bgcolor="#0d1421",

                    plot_bgcolor="#0d1421",

                    margin=dict(
                        l=10,
                        r=15,
                        t=5,
                        b=10
                    ),

                    font=dict(
                        color="#64748b",
                        size=9
                    ),

                    xaxis=dict(
                        showgrid=False,
                        zeroline=False
                    ),

                    yaxis=dict(
                        showgrid=True,
                        gridcolor="#172236",
                        zeroline=False
                    ),

                    hovermode="x unified"
                )


                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    config={
                        "displayModeBar": False
                    }
                )

            else:

                st.info(
                    "No failed login events found."
                )

        else:

            st.info(
                "No logs available."
            )


    # --------------------------------------------------------
    # THREAT SCORE
    # --------------------------------------------------------

    with score_col:

        html(f"""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Threat Level
                    </div>

                    <div class="panel-subtitle">
                        Current environment risk
                    </div>

                </div>

            </div>

            <div class="threat-score">

                <div class="score-circle">

                    <div class="score-number">
                        {threat_score}
                    </div>

                    <div class="score-label">
                        RISK SCORE
                    </div>

                </div>

                <div class="{threat_class}">
                    {threat_status} THREAT
                </div>

                <div style="
                    color:#64748b;
                    font-size:9px;
                    margin-top:7px;
                ">
                    Based on generated alerts
                </div>

            </div>

        </div>
        """)


    st.write("")


    # --------------------------------------------------------
    # RECENT ALERTS + ATTACK DISTRIBUTION
    # --------------------------------------------------------

    left, right = st.columns(
        2,
        gap="medium"
    )


    # ========================================================
    # RECENT ALERTS
    # ========================================================

    with left:

        html("""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Recent Security Alerts
                    </div>

                    <div class="panel-subtitle">
                        Latest alerts generated by detection rules
                    </div>

                </div>

            </div>
        """)


        if alerts:

            recent_alerts = alerts[:5]


            for alert in recent_alerts:

                severity = str(
                    alert.get(
                        "severity",
                        "LOW"
                    )
                ).upper()


                alert_type = alert.get(
                    "alert_type",
                    "Security Alert"
                )


                description = alert.get(
                    "description",
                    ""
                )


                ip = alert.get(
                    "ip_address",
                    "-"
                )


                timestamp = alert.get(
                    "timestamp",
                    "-"
                )


                html(f"""
                <div class="alert-row">

                    <div class="
                        severity
                        {severity_class(severity)}
                    ">
                        {severity}
                    </div>

                    <div class="alert-details">

                        <div class="alert-name">
                            {alert_type}
                        </div>

                        <div class="alert-meta">
                            {ip} • {description}
                        </div>

                    </div>

                    <div class="alert-time">
                        {timestamp}
                    </div>

                </div>
                """)

        else:

            st.info(
                "No security alerts generated yet."
            )


        html("""
        </div>
        """)


    # ========================================================
    # ATTACK DISTRIBUTION
    # ========================================================

    with right:

        html("""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Attack Distribution
                    </div>

                    <div class="panel-subtitle">
                        Alerts grouped by detection type
                    </div>

                </div>

                <div class="panel-badge">
                    DATABASE
                </div>

            </div>
        """)


        if alerts:

            alert_df = pd.DataFrame(
                alerts
            )


            if "alert_type" in alert_df.columns:

                attack_counts = (
                    alert_df["alert_type"]
                    .value_counts()
                    .head(5)
                )


                max_count = max(
                    int(attack_counts.max()),
                    1
                )


                for attack_name, count in attack_counts.items():

                    percentage = (
                        int(count)
                        / max_count
                    ) * 100


                    html(f"""
                    <div class="attack-item">

                        <div class="attack-header">

                            <span>
                                {attack_name}
                            </span>

                            <span class="attack-count">
                                {count}
                            </span>

                        </div>

                        <div class="progress-bg">

                            <div
                                class="progress-fill"
                                style="width:{percentage}%"
                            ></div>

                        </div>

                    </div>
                    """)

            else:

                st.info(
                    "No attack information available."
                )

        else:

            st.info(
                "No alerts available."
            )


        html("""
        </div>
        """)


    st.write("")


    # --------------------------------------------------------
    # SUSPICIOUS IPS + LOG SOURCES
    # --------------------------------------------------------

    ip_col, source_col = st.columns(
        2,
        gap="medium"
    )


    # ========================================================
    # SUSPICIOUS IPS
    # ========================================================

    with ip_col:

        html("""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Top Suspicious IPs
                    </div>

                    <div class="panel-subtitle">
                        IP addresses generating security alerts
                    </div>

                </div>

            </div>
        """)


        if alerts:

            alert_df = pd.DataFrame(
                alerts
            )


            if "ip_address" in alert_df.columns:

                ip_counts = (
                    alert_df[
                        alert_df["ip_address"].notna()
                    ]["ip_address"]
                    .astype(str)
                    .value_counts()
                    .head(5)
                )


                for ip, count in ip_counts.items():

                    if count >= 5:

                        risk = "HIGH"

                    elif count >= 3:

                        risk = "MEDIUM"

                    else:

                        risk = "LOW"


                    html(f"""
                    <div class="ip-row">

                        <div class="ip-address">
                            {ip}
                        </div>

                        <div class="ip-count">
                            {count} alerts
                        </div>

                        <div class="ip-risk">
                            {risk}
                        </div>

                    </div>
                    """)

            else:

                st.info(
                    "No IP information available."
                )

        else:

            st.info(
                "No suspicious IPs detected."
            )


        html("""
        </div>
        """)


    # ========================================================
    # LOG SOURCES
    # ========================================================

    with source_col:

        html(f"""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Log Sources
                    </div>

                    <div class="panel-subtitle">
                        Current data stored in the SIEM database
                    </div>

                </div>

                <div class="panel-badge">
                    {total_events} EVENTS
                </div>

            </div>

            <div class="source">

                <div class="source-name">
                    Authentication Logs
                </div>

                <div class="source-status">
                    ● ACTIVE
                </div>

            </div>

            <div class="source">

                <div class="source-name">
                    CSV Log Collection
                </div>

                <div class="source-status">
                    ● ACTIVE
                </div>

            </div>

            <div class="source">

                <div class="source-name">
                    MySQL Storage
                </div>

                <div class="source-status">
                    ● CONNECTED
                </div>

            </div>

        </div>
        """)


    # --------------------------------------------------------
    # FOOTER
    # --------------------------------------------------------

    html("""
    <div class="footer">

        <div>
            SENTINEL SOC • Security Monitoring Platform
        </div>

        <div>
            DATABASE EDITION • v1.0
        </div>

    </div>
    """)


# ============================================================
# LOG EXPLORER
# ============================================================

elif st.session_state.page == "Logs":

    html("""
    <div class="topbar">

        <div class="topbar-left">

            <div class="page-heading">
                Log Explorer
            </div>

            <div class="page-description">
                Search, filter and upload security logs
            </div>

        </div>

        <div class="live-pill">

            <div class="live-dot"></div>

            LOG ENGINE ACTIVE

        </div>

    </div>
    """)


    # --------------------------------------------------------
    # UPLOAD PANEL
    # --------------------------------------------------------

    html("""
    <div class="panel">

        <div class="panel-header">

            <div>

                <div class="panel-title">
                    Import Security Logs
                </div>

                <div class="panel-subtitle">
                    Upload a CSV file for parsing,
                    storage and detection
                </div>

            </div>

        </div>

    </div>
    """)


    uploaded_file = st.file_uploader(
        "Upload CSV log file",
        type=["csv"]
    )


    if uploaded_file is not None:

        if st.button(
            "🚀 Process Logs",
            type="primary"
        ):

            with st.spinner(
                "Parsing and processing logs..."
            ):

                try:

                    uploaded_file.seek(0)


                    parsed_df = parse_log_file(
                        uploaded_file
                    )


                    if parsed_df is None:

                        st.error(
                            "Unable to parse the uploaded file."
                        )

                    elif parsed_df.empty:

                        st.warning(
                            "The uploaded file contains no valid logs."
                        )

                    else:

                        # ------------------------------------
                        # INSERT LOGS
                        # ------------------------------------

                        inserted = (
                            save_logs_to_database(
                                parsed_df
                            )
                        )


                        # ------------------------------------
                        # RUN DETECTION
                        # ------------------------------------

                        alert_count_before = (
                            get_alert_count()
                        )


                        run_detection(
                            parsed_df
                        )


                        alert_count_after = (
                            get_alert_count()
                        )


                        actual_generated = (
                            alert_count_after
                            - alert_count_before
                        )


                        st.success(
                            f"{inserted} logs inserted successfully."
                        )


                        st.info(
                            f"{actual_generated} new security alerts generated."
                        )


                        st.rerun()


                except Exception as e:

                    st.error(
                        f"Processing error: {e}"
                    )


    st.write("")


    # --------------------------------------------------------
    # FILTER PANEL
    # --------------------------------------------------------

    html("""
    <div class="filter-panel">
    """)


    search = st.text_input(
        "Search logs",
        placeholder=(
            "Search by username, IP address, "
            "status or event type..."
        )
    )


    col1, col2, col3 = st.columns(3)


    with col1:

        status_filter = st.selectbox(
            "Status",
            [
                "All",
                "Success",
                "Failed"
            ]
        )


    with col2:

        event_filter = st.selectbox(
            "Event Type",
            [
                "All",
                "Login"
            ]
        )


    with col3:

        limit = st.selectbox(
            "Display",
            [
                25,
                50,
                100,
                500
            ]
        )


    html("""
    </div>
    """)


    # --------------------------------------------------------
    # DATABASE LOGS
    # --------------------------------------------------------

    logs = load_logs()

    if logs:

        df = pd.DataFrame(logs)

        # Make sure the table always has readable column names when
        # the database connector returns tuple-style rows.
        if all(isinstance(column, int) for column in df.columns):

            expected_columns = [
                "id",
                "username",
                "ip_address",
                "event_type",
                "status",
                "timestamp",
                "source"
            ]

            if len(df.columns) <= len(expected_columns):
                df.columns = expected_columns[:len(df.columns)]

        # Convert timestamp only when the column exists.
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(
                df["timestamp"],
                errors="coerce"
            )

        # ----------------------------------------------------
        # SEARCH
        # ----------------------------------------------------

        if search:

            search_text = search.lower().strip()

            if search_text:

                mask = (
                    df.astype(str)
                    .apply(
                        lambda column:
                        column.str.lower()
                        .str.contains(
                            search_text,
                            na=False,
                            regex=False
                        )
                    )
                    .any(axis=1)
                )

                df = df[mask]

        # ----------------------------------------------------
        # STATUS FILTER
        # ----------------------------------------------------

        if (
            status_filter != "All"
            and "status" in df.columns
        ):

            df = df[
                df["status"]
                .astype(str)
                .str.lower()
                == status_filter.lower()
            ]

        # ----------------------------------------------------
        # EVENT FILTER
        # ----------------------------------------------------

        if (
            event_filter != "All"
            and "event_type" in df.columns
        ):

            df = df[
                df["event_type"]
                .astype(str)
                .str.lower()
                == event_filter.lower()
            ]

        # Apply display limit after filtering.
        df = df.head(limit)

        # ----------------------------------------------------
        # STORED SECURITY LOGS
        # ----------------------------------------------------

        html(f"""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Stored Security Logs
                    </div>

                    <div class="panel-subtitle">
                        {len(df)} records displayed from MySQL
                    </div>

                </div>

                <div class="panel-badge">
                    {len(logs)} STORED
                </div>

            </div>

        </div>
        """)

        if not df.empty:

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.warning(
                "No logs match the selected filters."
            )

    else:

        html("""
        <div class="panel">

            <div class="panel-header">

                <div>

                    <div class="panel-title">
                        Stored Security Logs
                    </div>

                    <div class="panel-subtitle">
                        Security events stored in MySQL
                    </div>

                </div>

            </div>

        </div>
        """)

        st.info(
            "No logs are currently returned from the MySQL database."
        )

        st.caption(
            "Upload and process a CSV log file above, then refresh the page."
        )
        logs = load_logs()

    st.write("DEBUG - Logs returned from MySQL:", len(logs))
    st.write(logs)


# ============================================================
# SECURITY ALERTS
# ============================================================

elif st.session_state.page == "Alerts":

    html("""
    <div class="topbar">

        <div class="topbar-left">

            <div class="page-heading">
                Security Alerts
            </div>

            <div class="page-description">
                Detected threats requiring analyst attention
            </div>

        </div>

        <div class="live-pill">

            <div class="live-dot"></div>

            ALERT ENGINE ACTIVE

        </div>

    </div>
    """)


    alerts = load_alerts()


    if alerts:

        alert_df = pd.DataFrame(
            alerts
        )


        # ----------------------------------------------------
        # FILTERS
        # ----------------------------------------------------

        col1, col2, col3 = st.columns(3)


        with col1:

            severity_filter = st.selectbox(
                "Severity",
                [
                    "All",
                    "Critical",
                    "High",
                    "Medium",
                    "Low"
                ]
            )


        with col2:

            status_filter = st.selectbox(
                "Status",
                [
                    "All",
                    "Open",
                    "Investigating",
                    "Resolved"
                ]
            )


        with col3:

            alert_search = st.text_input(
                "Search alerts",
                placeholder=(
                    "Alert type, IP, username..."
                )
            )


        filtered = alert_df.copy()


        # Severity

        if severity_filter != "All":

            filtered = filtered[
                filtered["severity"]
                .astype(str)
                .str.lower()
                == severity_filter.lower()
            ]


        # Status

        if status_filter != "All":

            filtered = filtered[
                filtered["status"]
                .astype(str)
                .str.lower()
                == status_filter.lower()
            ]


        # Search

        if alert_search:

            search_text = (
                alert_search.lower()
            )


            mask = (
                filtered.astype(str)
                .apply(
                    lambda column:
                    column.str.lower()
                    .str.contains(
                        search_text,
                        na=False
                    )
                )
                .any(axis=1)
            )


            filtered = filtered[mask]


        st.write("")


        # ----------------------------------------------------
        # ALERT SUMMARY
        # ----------------------------------------------------

        a1, a2, a3 = st.columns(3)


        with a1:

            st.metric(
                "Total Alerts",
                len(filtered)
            )


        with a2:

            high_count = len(
                filtered[
                    filtered["severity"]
                    .astype(str)
                    .str.lower()
                    == "high"
                ]
            )


            st.metric(
                "High Severity",
                high_count
            )


        with a3:

            critical_count = len(
                filtered[
                    filtered["severity"]
                    .astype(str)
                    .str.lower()
                    == "critical"
                ]
            )


            st.metric(
                "Critical",
                critical_count
            )


        st.write("")


        # ----------------------------------------------------
        # ALERT TABLE
        # ----------------------------------------------------

        display_columns = [
            "id",
            "alert_type",
            "description",
            "severity",
            "username",
            "ip_address",
            "timestamp",
            "status"
        ]


        available_columns = [
            column
            for column in display_columns
            if column in filtered.columns
        ]


        st.dataframe(
            filtered[available_columns],
            use_container_width=True,
            hide_index=True
        )


    else:

        st.success(
            "No security alerts have been generated yet."
        )


# ============================================================
# THREAT ANALYSIS
# ============================================================

elif st.session_state.page == "Analysis":

    html("""
    <div class="topbar">

        <div class="topbar-left">

            <div class="page-heading">
                Threat Analysis
            </div>

            <div class="page-description">
                Analyze attack patterns and security activity
            </div>

        </div>

    </div>
    """)


    alerts = load_alerts()


    if alerts:

        alert_df = pd.DataFrame(
            alerts
        )


        # ----------------------------------------------------
        # SEVERITY ANALYSIS
        # ----------------------------------------------------

        if "severity" in alert_df.columns:

            severity_data = (
                alert_df["severity"]
                .astype(str)
                .str.upper()
                .value_counts()
                .reset_index()
            )


            severity_data.columns = [
                "Severity",
                "Count"
            ]


            a1, a2 = st.columns(2)


            # ------------------------------------------------
            # BAR CHART
            # ------------------------------------------------

            with a1:

                fig = px.bar(
                    severity_data,
                    x="Severity",
                    y="Count",
                    title="Alerts by Severity"
                )


                fig.update_layout(
                    paper_bgcolor="#0d1421",
                    plot_bgcolor="#0d1421",

                    font=dict(
                        color="#94a3b8"
                    ),

                    height=350
                )


                st.plotly_chart(
                    fig,
                    use_container_width=True
                )


            # ------------------------------------------------
            # PIE CHART
            # ------------------------------------------------

            with a2:

                fig2 = px.pie(
                    severity_data,
                    names="Severity",
                    values="Count",
                    hole=0.55,
                    title="Threat Distribution"
                )


                fig2.update_layout(
                    paper_bgcolor="#0d1421",
                    plot_bgcolor="#0d1421",

                    font=dict(
                        color="#94a3b8"
                    ),

                    height=350
                )


                st.plotly_chart(
                    fig2,
                    use_container_width=True
                )


        # ----------------------------------------------------
        # ALERT TYPE ANALYSIS
        # ----------------------------------------------------

        if "alert_type" in alert_df.columns:

            type_data = (
                alert_df["alert_type"]
                .value_counts()
                .reset_index()
            )


            type_data.columns = [
                "Alert Type",
                "Count"
            ]


            st.subheader(
                "Detection Rule Activity"
            )


            st.dataframe(
                type_data,
                use_container_width=True,
                hide_index=True
            )


    else:

        st.info(
            "Threat analysis will appear after security alerts are generated."
        )


# ============================================================
# SECURITY REPORTS
# ============================================================

elif st.session_state.page == "Reports":

    html("""
    <div class="topbar">

        <div class="topbar-left">

            <div class="page-heading">
                Security Reports
            </div>

            <div class="page-description">
                Generate security monitoring reports
                from stored data
            </div>

        </div>

    </div>
    """)

    logs = load_logs()
    alerts = load_alerts()

    total_events = len(logs)
    total_alerts = len(alerts)

    high_count = get_high_alert_count()
    critical_count = get_critical_alert_count()

    medium_count = sum(
        1
        for alert in alerts
        if str(alert.get("severity", "")).strip().lower() == "medium"
    )

    threat_score = get_threat_score(
        total_alerts,
        high_count,
        critical_count
    )

    threat_status = get_threat_status(
        threat_score
    )

    # --------------------------------------------------------
    # REPORT METRICS
    # --------------------------------------------------------

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.metric("Total Events", total_events)

    with c2:
        st.metric("Security Alerts", total_alerts)

    with c3:
        st.metric("High Severity", high_count)

    with c4:
        st.metric("Critical", critical_count)

    with c5:
        st.metric("Threat Score", threat_score)

    st.write("")

    # --------------------------------------------------------
    # THREAT STATUS
    # --------------------------------------------------------

    if threat_status == "HIGH":
        st.error(f"Threat Level: {threat_status}")

    elif threat_status == "MEDIUM":
        st.warning(f"Threat Level: {threat_status}")

    else:
        st.success(f"Threat Level: {threat_status}")

    st.write("")

    # --------------------------------------------------------
    # DOWNLOAD REPORTS
    # --------------------------------------------------------

    if alerts:

        report_df = pd.DataFrame(alerts)

        pdf_data = generate_pdf_report(
            logs=logs,
            alerts=alerts,
            total_events=total_events,
            total_alerts=total_alerts,
            high_count=high_count,
            critical_count=critical_count,
            threat_score=threat_score,
            threat_status=threat_status
        )

        st.download_button(
            label="📑 Download PDF Report",
            data=pdf_data,
            file_name="sentinel_security_report.pdf",
            mime="application/pdf",
            use_container_width=True
        )

        st.write("")

        # ----------------------------------------------------
        # REPORT PREVIEW
        # ----------------------------------------------------

        st.subheader(
            "Security Alert Report"
        )

        st.dataframe(
            report_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No alert data available for the report."
        )


# ============================================================
# SETTINGS
# ============================================================

elif st.session_state.page == "Settings":

    html("""
    <div class="topbar">

        <div class="topbar-left">

            <div class="page-heading">
                System Settings
            </div>

            <div class="page-description">
                Configure monitoring and dashboard preferences
            </div>

        </div>

    </div>
    """)


    # --------------------------------------------------------
    # MONITORING
    # --------------------------------------------------------

    st.subheader(
        "Monitoring"
    )


    monitoring = st.toggle(
        "Enable Monitoring Dashboard",
        value=True
    )


    alerts_enabled = st.toggle(
        "Enable Security Alerts",
        value=True
    )


    auto_refresh = st.toggle(
        "Automatic Log Refresh",
        value=False
    )


    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    st.subheader(
        "Dashboard"
    )


    refresh_interval = st.selectbox(
        "Dashboard Refresh Interval",
        [
            "10 seconds",
            "30 seconds",
            "1 minute",
            "5 minutes"
        ]
    )


    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    st.subheader(
        "Database"
    )


    st.success(
        "MySQL database connection is configured."
    )


    st.info(
        "The current version reads stored logs from MySQL. "
        "True real-time log collection will be implemented "
        "in the next stage."
    )


    # --------------------------------------------------------
    # CURRENT CONFIGURATION
    # --------------------------------------------------------

    st.write("")


    html(f"""
    <div class="panel">

        <div class="panel-title">
            Current Configuration
        </div>

        <br>

        <div class="alert-meta">

            Monitoring:
            <b>
                {"Enabled" if monitoring else "Disabled"}
            </b>

            <br><br>

            Security Alerts:
            <b>
                {"Enabled" if alerts_enabled else "Disabled"}
            </b>

            <br><br>

            Automatic Refresh:
            <b>
                {"Enabled" if auto_refresh else "Disabled"}
            </b>

            <br><br>

            Refresh Interval:
            <b>
                {refresh_interval}
            </b>

        </div>

    </div>
    """)