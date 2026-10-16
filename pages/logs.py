import streamlit as st
import pandas as pd

from components.ui import html, page_header
from pages.common import load_logs
from log_parser import parse_log_file, save_logs_to_database
from detection_engine import run_detection
from database import get_alert_count

def show_logs():
    page_header("Log Explorer", "Upload, search and filter stored security logs", "LOG ENGINE")

    with st.expander("Import security logs", expanded=True):
        uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"], key="log_csv_upload")
        st.caption("Required columns: timestamp, username, ip_address, status, event_type")
        if uploaded_file is not None and st.button("Process Logs", type="primary"):
            try:
                uploaded_file.seek(0)
                parsed = parse_log_file(uploaded_file)
                if parsed is None:
                    st.error("The file could not be parsed. Check the required column names.")
                elif parsed.empty:
                    st.warning("No valid rows were found in the uploaded CSV.")
                else:
                    inserted = save_logs_to_database(parsed)
                    before = get_alert_count()
                    run_detection(parsed)
                    after = get_alert_count()
                    st.success(f"{inserted} log rows inserted into MySQL.")
                    st.info(f"{max(0, after - before)} new alerts generated.")
                    st.rerun()
            except Exception as exc:
                st.error(f"Could not process uploaded logs: {exc}")

    logs = load_logs()
    if logs.empty:
        st.info("No logs are stored yet. Upload a CSV file to begin.")
        return

    st.subheader("Search and filter")
    search = st.text_input("Search logs", placeholder="Username, IP address, status, event type...")
    c1, c2, c3 = st.columns(3)
    with c1:
        status_options = ["All"] + sorted(logs["status"].dropna().astype(str).unique().tolist()) if "status" in logs else ["All"]
        status_filter = st.selectbox("Status", status_options)
    with c2:
        event_options = ["All"] + sorted(logs["event_type"].dropna().astype(str).unique().tolist()) if "event_type" in logs else ["All"]
        event_filter = st.selectbox("Event type", event_options)
    with c3:
        limit = st.selectbox("Rows to display", [25, 50, 100, 500], index=1)

    filtered = logs.copy()
    if search:
        mask = filtered.astype(str).apply(
            lambda col: col.str.contains(search, case=False, na=False)
        ).any(axis=1)
        filtered = filtered[mask]
    if status_filter != "All" and "status" in filtered:
        filtered = filtered[filtered["status"].astype(str) == status_filter]
    if event_filter != "All" and "event_type" in filtered:
        filtered = filtered[filtered["event_type"].astype(str) == event_filter]

    st.caption(f"{len(filtered)} matching records")
    st.dataframe(filtered.head(limit), use_container_width=True, hide_index=True)

    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download filtered logs as CSV",
        data=csv,
        file_name="filtered_security_logs.csv",
        mime="text/csv"
    )
