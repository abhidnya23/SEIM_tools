import streamlit as st
import pandas as pd

from components.ui import page_header
from pages.common import load_alerts
from database import (
    update_alert_status,
    get_alert_status_counts
)


def show_alerts():
    page_header(
        "Security Alerts",
        "Review, investigate, and manage security alerts",
        "ALERT ENGINE"
    )

    alerts = load_alerts()

    if alerts.empty:
        st.info(
            "No alerts are stored yet. Upload logs in Log Explorer "
            "to run the detection engine."
        )
        return

    # Ensure the new notes column is available in the display.
    if "investigation_notes" not in alerts.columns:
        alerts["investigation_notes"] = ""

    # ==========================================
    # 1. ALERT STATUS SUMMARY
    # ==========================================

    status_counts = get_alert_status_counts()

    st.subheader("Investigation Overview")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric(
            "New Alerts",
            status_counts.get("NEW", 0)
        )

    with c2:
        st.metric(
            "Investigating",
            status_counts.get("INVESTIGATING", 0)
        )

    with c3:
        st.metric(
            "Resolved",
            status_counts.get("RESOLVED", 0)
        )

    st.divider()

    # ==========================================
    # 2. FILTER ALERTS
    # ==========================================

    c1, c2, c3 = st.columns(3)

    with c1:
        severity_options = ["All"]

        if "severity" in alerts.columns:
            severity_options += sorted(
                alerts["severity"]
                .dropna()
                .astype(str)
                .str.upper()
                .unique()
                .tolist()
            )

        severity = st.selectbox(
            "Severity",
            severity_options
        )

    with c2:
        status_options = [
            "All",
            "NEW",
            "INVESTIGATING",
            "RESOLVED"
        ]

        status = st.selectbox(
            "Investigation Status",
            status_options
        )

    with c3:
        search = st.text_input(
            "Search Alerts",
            placeholder="Alert, IP, username..."
        )

    filtered = alerts.copy()

    if severity != "All" and "severity" in filtered.columns:
        filtered = filtered[
            filtered["severity"]
            .astype(str)
            .str.upper() == severity
        ]

    if status != "All" and "status" in filtered.columns:
        filtered = filtered[
            filtered["status"]
            .fillna("NEW")
            .astype(str)
            .str.upper() == status
        ]

    if search.strip():
        mask = filtered.astype(str).apply(
            lambda col: col.str.contains(
                search.strip(),
                case=False,
                na=False,
                regex=False
            )
        ).any(axis=1)

        filtered = filtered[mask]

    # ==========================================
    # 3. ALERT STATISTICS
    # ==========================================

    st.subheader("Alert Statistics")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric(
            "Matching Alerts",
            len(filtered)
        )

    with c2:
        high = 0

        if "severity" in filtered.columns:
            high = int(
                (
                    filtered["severity"]
                    .astype(str)
                    .str.upper() == "HIGH"
                ).sum()
            )

        st.metric("High Severity", high)

    with c3:
        critical = 0

        if "severity" in filtered.columns:
            critical = int(
                (
                    filtered["severity"]
                    .astype(str)
                    .str.upper() == "CRITICAL"
                ).sum()
            )

        st.metric("Critical Severity", critical)

    # ==========================================
    # 4. ALERT TABLE
    # ==========================================

    st.subheader("Alert Records")

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True
    )

    # ==========================================
    # 5. INVESTIGATE AN ALERT
    # ==========================================

    st.divider()

    st.subheader("Investigate Alert")

    if "id" not in filtered.columns:
        st.error("Alert IDs are required to update alerts.")
        return

    if filtered.empty:
        st.info("No alerts match your current filters.")
        return

    alert_ids = filtered["id"].tolist()

    selected_id = st.selectbox(
        "Select Alert ID",
        alert_ids
    )

    selected_rows = filtered[
        filtered["id"] == selected_id
    ]

    if selected_rows.empty:
        st.warning("The selected alert could not be found.")
        return

    selected_alert = selected_rows.iloc[0]

    st.markdown("### Selected Alert Details")

    col1, col2 = st.columns(2)

    with col1:
        st.write(
            "**Alert Type:**",
            selected_alert.get("alert_type", "Unknown")
        )

        st.write(
            "**Severity:**",
            selected_alert.get("severity", "Unknown")
        )

        st.write(
            "**Username:**",
            selected_alert.get("username", "Unknown")
        )

    with col2:
        st.write(
            "**IP Address:**",
            selected_alert.get("ip_address", "Unknown")
        )

        st.write(
            "**Timestamp:**",
            str(selected_alert.get("timestamp", "Unknown"))
        )

        st.write(
            "**Description:**",
            selected_alert.get("description", "No description")
        )

    current_status = str(
        selected_alert.get("status") or "NEW"
    ).upper()

    allowed_statuses = [
        "NEW",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if current_status not in allowed_statuses:
        current_status = "NEW"

    current_notes = selected_alert.get(
        "investigation_notes", ""
    )

    if pd.isna(current_notes):
        current_notes = ""

    with st.form("investigate_alert_form"):
        new_status = st.selectbox(
            "Update Investigation Status",
            allowed_statuses,
            index=allowed_statuses.index(current_status)
        )

        notes = st.text_area(
            "Investigation Notes",
            value=str(current_notes),
            placeholder=(
                "Example: Reviewed login attempts from this IP. "
                "Further investigation is required."
            )
        )

        submitted = st.form_submit_button(
            "Save Investigation"
        )

        if submitted:
            success = update_alert_status(
                selected_id,
                new_status,
                notes.strip()
            )

            if success:
                st.success(
                    f"Alert #{selected_id} updated successfully."
                )

                st.rerun()

            else:
                st.error(
                    "The alert could not be updated. "
                    "Check the database connection and alert ID."
                )

    # ==========================================
    # 6. DOWNLOAD FILTERED ALERTS
    # ==========================================

    st.divider()

    st.download_button(
        "Download Alerts CSV",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="security_alerts.csv",
        mime="text/csv"
    )