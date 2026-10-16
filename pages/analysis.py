import streamlit as st
import pandas as pd
import plotly.express as px

from components.ui import page_header
from pages.common import load_alerts, load_logs

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def show_analysis():
    page_header(
        "Threat Analysis",
        "Analyze alert severity, detection patterns, and suspicious IP activity",
        "THREAT ANALYSIS"
    )

    # ==========================================
    # 1. LOAD ALERTS
    # ==========================================
    alerts = load_alerts()

    # ==========================================
    # 2. ALERT SEVERITY ANALYSIS
    # ==========================================
    st.subheader("Alert Severity Analysis")

    if alerts.empty:
        st.info("Threat charts will appear when alerts exist in the database.")

    elif "severity" not in alerts.columns:
        st.error("The alerts table does not contain a severity column.")

    else:
        severity = (
            alerts["severity"]
            .fillna("LOW")
            .astype(str)
            .str.upper()
        )

        counts = severity.value_counts().reindex(
            SEVERITY_ORDER, fill_value=0
        )

        severity_df = counts.rename_axis(
            "Severity"
        ).reset_index(name="Count")

        left, right = st.columns(2, gap="medium")

        with left:
            st.subheader("Alerts by Severity")

            fig = px.bar(
                severity_df,
                x="Severity",
                y="Count",
                category_orders={"Severity": SEVERITY_ORDER}
            )

            fig.update_layout(
                paper_bgcolor="#0d1421",
                plot_bgcolor="#0d1421",
                font=dict(color="#94a3b8"),
                height=350,
                margin=dict(l=15, r=15, t=25, b=15),
                xaxis=dict(showgrid=False),
                yaxis=dict(
                    gridcolor="#172236",
                    rangemode="tozero"
                )
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False}
            )

        with right:
            st.subheader("Threat Distribution")

            fig = px.pie(
                severity_df,
                names="Severity",
                values="Count",
                hole=0.55,
                category_orders={"Severity": SEVERITY_ORDER}
            )

            fig.update_layout(
                paper_bgcolor="#0d1421",
                plot_bgcolor="#0d1421",
                font=dict(color="#94a3b8"),
                height=350,
                margin=dict(l=15, r=15, t=25, b=15)
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
                config={"displayModeBar": False}
            )

        st.subheader("Severity Summary")

        cols = st.columns(4)

        for col, sev in zip(cols, SEVERITY_ORDER):
            with col:
                st.metric(sev.title(), int(counts[sev]))

        if "alert_type" in alerts.columns:
            st.subheader("Detection Rule Activity")

            type_df = (
                alerts["alert_type"]
                .fillna("Unknown")
                .value_counts()
                .rename_axis("Alert Type")
                .reset_index(name="Count")
            )

            st.dataframe(
                type_df,
                use_container_width=True,
                hide_index=True
            )

    # ==========================================
    # 3. SUSPICIOUS IP ACTIVITY ANALYSIS
    # ==========================================
    st.divider()

    st.subheader("Suspicious IP Activity Analysis")

    logs = load_logs()

    if logs.empty:
        st.info(
            "IP activity analysis will appear when logs exist in the database."
        )
        return

    required_columns = {"ip_address", "status"}

    if not required_columns.issubset(logs.columns):
        st.error(
            "The logs must contain 'ip_address' and 'status' columns."
        )
        return

    # Normalize values for analysis.
    logs = logs.copy()

    logs["ip_address"] = (
        logs["ip_address"]
        .fillna("Unknown")
        .astype(str)
        .str.strip()
    )

    logs["status"] = (
        logs["status"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.upper()
    )

    # Count total attempts and failed attempts for each IP.
    ip_summary = (
        logs.groupby("ip_address")
        .agg(
            Total_Attempts=("status", "size"),
            Failed_Attempts=(
                "status",
                lambda values: values.isin(
                    ["FAILED", "FAIL", "FAILURE"]
                ).sum()
            )
        )
        .reset_index()
    )

    # Calculate the percentage of failed attempts.
    ip_summary["Failure_Rate"] = (
        ip_summary["Failed_Attempts"]
        / ip_summary["Total_Attempts"].replace(0, 1)
        * 100
    ).round(2)

    # Assign an activity-based risk category.
    def classify_ip(row):
        failed = row["Failed_Attempts"]
        total = row["Total_Attempts"]

        if failed >= 5:
            return "HIGH"
        elif failed >= 3:
            return "MEDIUM"
        elif total > 0 and failed > 0:
            return "LOW"
        else:
            return "NORMAL"

    ip_summary["Risk_Level"] = ip_summary.apply(
        classify_ip,
        axis=1
    )

    # Show summary metrics.
    high_risk = int(
        (ip_summary["Risk_Level"] == "HIGH").sum()
    )

    medium_risk = int(
        (ip_summary["Risk_Level"] == "MEDIUM").sum()
    )

    total_ips = len(ip_summary)

    col1, col2, col3 = st.columns(3)

    col1.metric("Unique IP Addresses", total_ips)
    col2.metric("High-Risk IPs", high_risk)
    col3.metric("Medium-Risk IPs", medium_risk)

    # Show only IPs with at least one failed attempt.
    suspicious_ips = ip_summary[
        ip_summary["Failed_Attempts"] > 0
    ].copy()

    suspicious_ips = suspicious_ips.sort_values(
        by=["Failed_Attempts", "Total_Attempts"],
        ascending=False
    )

    st.subheader("IP Activity Details")

    if suspicious_ips.empty:
        st.success("No failed login attempts were found in the loaded logs.")

    else:
        search_ip = st.text_input(
            "Search IP Address",
            placeholder="Enter an IP address..."
        )

        if search_ip.strip():
            suspicious_ips = suspicious_ips[
                suspicious_ips["ip_address"].str.contains(
                    search_ip.strip(),
                    case=False,
                    regex=False
                )
            ]

        display_df = suspicious_ips.rename(
            columns={
                "ip_address": "IP Address",
                "Total_Attempts": "Total Attempts",
                "Failed_Attempts": "Failed Attempts",
                "Failure_Rate": "Failure Rate (%)",
                "Risk_Level": "Risk Level"
            }
        )

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )

    # Visualize the IP addresses with the most failed attempts.
    st.subheader("Top IP Addresses by Failed Logins")

    top_ips = ip_summary[
        ip_summary["Failed_Attempts"] > 0
    ].nlargest(10, "Failed_Attempts")

    if not top_ips.empty:
        fig = px.bar(
            top_ips,
            x="ip_address",
            y="Failed_Attempts",
            hover_data=["Total_Attempts", "Failure_Rate", "Risk_Level"],
            labels={
                "ip_address": "IP Address",
                "Failed_Attempts": "Failed Login Attempts"
            }
        )

        fig.update_layout(
            paper_bgcolor="#0d1421",
            plot_bgcolor="#0d1421",
            font=dict(color="#94a3b8"),
            height=350,
            margin=dict(l=15, r=15, t=25, b=15),
            xaxis=dict(showgrid=False),
            yaxis=dict(
                gridcolor="#172236",
                rangemode="tozero"
            )
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={"displayModeBar": False}
        )