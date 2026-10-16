# ---------------- CURRENT PREFERENCES ----------------

st.subheader("Current Preferences")

monitoring_status = "ENABLED" if monitoring else "DISABLED"
alerts_status = "ENABLED" if alerts_enabled else "DISABLED"
refresh_status = "ENABLED" if auto_refresh else "DISABLED"

monitoring_color = "#4ade80" if monitoring else "#f87171"
alerts_color = "#4ade80" if alerts_enabled else "#f87171"
refresh_color = "#4ade80" if auto_refresh else "#fbbf24"

st.markdown(
    f"""
    <div class="panel">

        <div class="panel-header">
            <div>
                <div class="panel-title">Monitoring Dashboard</div>
                <div class="panel-subtitle">
                    Dashboard display preference
                </div>
            </div>
            <span style="color:{monitoring_color};
                         font-size:11px;font-weight:700;">
                {monitoring_status}
            </span>
        </div>

        <div class="panel-header">
            <div>
                <div class="panel-title">Security Alerts</div>
                <div class="panel-subtitle">
                    Display security alerts in the application
                </div>
            </div>
            <span style="color:{alerts_color};
                         font-size:11px;font-weight:700;">
                {alerts_status}
            </span>
        </div>

        <div class="panel-header">
            <div>
                <div class="panel-title">Automatic Refresh</div>
                <div class="panel-subtitle">
                    Automatic dashboard refresh preference
                </div>
            </div>
            <span style="color:{refresh_color};
                         font-size:11px;font-weight:700;">
                {refresh_status}
            </span>
        </div>

        <div class="panel-header">
            <div>
                <div class="panel-title">Refresh Interval</div>
                <div class="panel-subtitle">
                    Selected refresh interval
                </div>
            </div>
            <span style="color:#38bdf8;
                         font-size:11px;font-weight:700;">
                {refresh_interval.upper()}
            </span>
        </div>

    </div>
    """,
    unsafe_allow_html=True
)