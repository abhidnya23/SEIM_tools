import streamlit as st
from datetime import datetime
from io import BytesIO

from components.ui import page_header
from pages.common import load_logs, load_alerts
from database import get_high_alert_count, get_critical_alert_count

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# =========================================================
# GENERATE PDF REPORT
# =========================================================

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
    """Generate a PDF security report from Sentinel SOC data."""

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=29,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#172236"),
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=8
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#172236"),
        spaceBefore=14,
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
        leading=9,
        wordWrap="CJK"
    )

    header_style = ParagraphStyle(
        "TableHeader",
        parent=small_style,
        textColor=colors.white,
        fontName="Helvetica-Bold"
    )

    story = []

    # -----------------------------------------------------
    # REPORT HEADER
    # -----------------------------------------------------

    story.append(Paragraph("SENTINEL SOC", title_style))

    story.append(
        Paragraph(
            "SECURITY MONITORING AND INCIDENT REPORT",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            "Generated: "
            + datetime.now().strftime("%d %B %Y, %H:%M:%S"),
            subtitle_style
        )
    )

    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "This report provides an overview of security events, "
            "detected threats, alert severity, and detection activity "
            "recorded by the Sentinel SOC monitoring platform.",
            normal_style
        )
    )

    # -----------------------------------------------------
    # 1. SECURITY METRICS
    # -----------------------------------------------------

    story.append(
        Paragraph("1. Security Metrics", heading_style)
    )

    metrics = [
        ["Metric", "Value"],
        ["Total Events", str(total_events)],
        ["Security Alerts", str(total_alerts)],
        ["High Severity Alerts", str(high_count)],
        ["Critical Alerts", str(critical_count)],
        ["Threat Score", f"{threat_score}/100"],
        ["Threat Level", str(threat_status).upper()]
    ]

    metrics_table = Table(
        metrics,
        colWidths=[75 * mm, 75 * mm],
        repeatRows=1
    )

    metrics_table.setStyle(
        TableStyle([
            (
                "BACKGROUND", (0, 0), (-1, 0),
                colors.HexColor("#172236")
            ),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            (
                "BACKGROUND", (0, 1), (-1, -1),
                colors.HexColor("#F1F5F9")
            ),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#172236")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
        ])
    )

    story.append(metrics_table)

    # -----------------------------------------------------
    # 2. ALERT SEVERITY SUMMARY
    # -----------------------------------------------------

    story.append(
        Paragraph("2. Alert Severity Summary", heading_style)
    )

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for alert in alerts:
        severity = str(
            alert.get("severity", "Low") or "Low"
        ).strip().capitalize()

        if severity in severity_counts:
            severity_counts[severity] += 1

    severity_data = [
        [
            Paragraph("Severity", header_style),
            Paragraph("Number of Alerts", header_style)
        ]
    ]

    for severity, count in severity_counts.items():
        severity_data.append([severity, str(count)])

    severity_table = Table(
        severity_data,
        colWidths=[75 * mm, 75 * mm],
        repeatRows=1
    )

    severity_table.setStyle(
        TableStyle([
            (
                "BACKGROUND", (0, 0), (-1, 0),
                colors.HexColor("#172236")
            ),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            (
                "ROWBACKGROUNDS", (0, 1), (-1, -1),
                [colors.white, colors.HexColor("#F1F5F9")]
            ),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(severity_table)

    # -----------------------------------------------------
    # 3. SECURITY ALERT DETAILS
    # -----------------------------------------------------

    story.append(
        Paragraph("3. Security Alert Details", heading_style)
    )

    alert_columns = [
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
        available_alert_columns = [
            col for col in alert_columns
            if any(col in alert for alert in alerts)
        ]
    else:
        available_alert_columns = []

    available_width = (
        landscape(A4)[0] - doc.leftMargin - doc.rightMargin
    )

    if available_alert_columns:

        alert_table_data = [
            [
                Paragraph(
                    col.replace("_", " ").title(),
                    header_style
                )
                for col in available_alert_columns
            ]
        ]

        for alert in alerts:
            row = []

            for col in available_alert_columns:
                value = alert.get(col, "")

                if value is None:
                    value = ""

                safe_value = (
                    str(value)
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                )

                row.append(Paragraph(safe_value, small_style))

            alert_table_data.append(row)

        preferred_widths = {
            "id": 12,
            "alert_type": 28,
            "description": 55,
            "severity": 20,
            "username": 25,
            "ip_address": 27,
            "timestamp": 32,
            "status": 20
        }

        weights = [
            preferred_widths.get(col, 25)
            for col in available_alert_columns
        ]

        total_weight = sum(weights)

        column_widths = [
            available_width * weight / total_weight
            for weight in weights
        ]

        alert_table = Table(
            alert_table_data,
            colWidths=column_widths,
            repeatRows=1
        )

        alert_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND", (0, 0), (-1, 0),
                    colors.HexColor("#172236")
                ),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                (
                    "ROWBACKGROUNDS", (0, 1), (-1, -1),
                    [colors.white, colors.HexColor("#F1F5F9")]
                )
            ])
        )

        story.append(alert_table)

    else:
        story.append(
            Paragraph("No security alert details available.", normal_style)
        )

    # -----------------------------------------------------
    # 4. SECURITY LOG DETAILS
    # -----------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph("4. Security Log Details", heading_style)
    )

    log_columns = [
        "id",
        "timestamp",
        "username",
        "ip_address",
        "status",
        "event_type"
    ]

    if logs:
        available_log_columns = [
            col for col in log_columns
            if any(col in log for log in logs)
        ]
    else:
        available_log_columns = []

    if available_log_columns:

        log_table_data = [
            [
                Paragraph(
                    col.replace("_", " ").title(),
                    header_style
                )
                for col in available_log_columns
            ]
        ]

        for log in logs:
            row = []

            for col in available_log_columns:
                value = log.get(col, "")

                if value is None:
                    value = ""

                safe_value = (
                    str(value)
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                )

                row.append(Paragraph(safe_value, small_style))

            log_table_data.append(row)

        log_table = Table(
            log_table_data,
            colWidths=[
                available_width / len(available_log_columns)
            ] * len(available_log_columns),
            repeatRows=1
        )

        log_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND", (0, 0), (-1, 0),
                    colors.HexColor("#1E3A8A")
                ),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                (
                    "ROWBACKGROUNDS", (0, 1), (-1, -1),
                    [colors.white, colors.HexColor("#F1F5F9")]
                )
            ])
        )

        story.append(log_table)

    else:
        story.append(
            Paragraph("No security log details available.", normal_style)
        )

    # -----------------------------------------------------
    # 5. DETECTION RULE ACTIVITY
    # -----------------------------------------------------

    story.append(
        Paragraph("5. Detection Rule Activity", heading_style)
    )

    alert_types = {}

    for alert in alerts:
        alert_type = str(
            alert.get("alert_type", "Unknown") or "Unknown"
        )

        alert_types[alert_type] = (
            alert_types.get(alert_type, 0) + 1
        )

    type_data = [
        [
            Paragraph("Detection Rule", header_style),
            Paragraph("Alert Count", header_style)
        ]
    ]

    for alert_type, count in sorted(
        alert_types.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        safe_alert_type = (
            alert_type
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        type_data.append([
            Paragraph(safe_alert_type, small_style),
            str(count)
        ])

    if len(type_data) > 1:

        type_table = Table(
            type_data,
            colWidths=[
                available_width * 0.75,
                available_width * 0.25
            ],
            repeatRows=1
        )

        type_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND", (0, 0), (-1, 0),
                    colors.HexColor("#172236")
                ),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                (
                    "ROWBACKGROUNDS", (0, 1), (-1, -1),
                    [colors.white, colors.HexColor("#F1F5F9")]
                ),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
            ])
        )

        story.append(type_table)

    else:
        story.append(
            Paragraph("No detection rule activity available.", normal_style)
        )

    # -----------------------------------------------------
    # 6. REPORT SUMMARY
    # -----------------------------------------------------

    story.append(
        Paragraph("6. Report Summary", heading_style)
    )

    summary_text = (
        f"The Sentinel SOC system recorded {total_events} security events "
        f"and generated {total_alerts} security alerts. "
        f"There were {high_count} high-severity alerts and "
        f"{critical_count} critical alerts. "
        f"The calculated threat score is {threat_score}/100, "
        f"classified as {str(threat_status).upper()}."
    )

    story.append(Paragraph(summary_text, normal_style))
    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "SENTINEL SOC | Security Monitoring Platform | Version 1.0",
            subtitle_style
        )
    )

    # Generate PDF
    doc.build(story)

    buffer.seek(0)

    return buffer.getvalue()


# =========================================================
# STREAMLIT REPORTS PAGE
# =========================================================

def show_reports():

    page_header(
        "Security Reports",
        "Generate and download security reports in PDF format",
        "REPORTS"
    )

    # Load data
    logs_df = load_logs()
    alerts_df = load_alerts()

    # Convert DataFrames to lists of dictionaries
    logs = logs_df.to_dict(orient="records")
    alerts = alerts_df.to_dict(orient="records")

    # Calculate metrics
    total_events = len(logs)
    total_alerts = len(alerts)

    high_count = get_high_alert_count()
    critical_count = get_critical_alert_count()

    # Threat score calculation
    threat_score = min(
        100,
        total_alerts + (5 * high_count) + (10 * critical_count)
    )

    if threat_score >= 70:
        threat_status = "HIGH"
    elif threat_score >= 40:
        threat_status = "MEDIUM"
    else:
        threat_status = "LOW"

    # -----------------------------------------------------
    # DISPLAY METRICS
    # -----------------------------------------------------

    st.subheader("Security Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", total_events)
    col2.metric("Security Alerts", total_alerts)
    col3.metric("High Severity", high_count)
    col4.metric("Critical", critical_count)

    col1, col2 = st.columns(2)

    col1.metric("Threat Score", f"{threat_score}/100")
    col2.metric("Threat Level", threat_status)

    st.divider()

    # -----------------------------------------------------
    # PDF GENERATION AND DOWNLOAD
    # -----------------------------------------------------

    st.subheader("Export Security Report")

    st.write(
        "Generate a comprehensive PDF report containing security metrics, "
        "alert severity, security logs, alert details, and detection rules."
    )

    if st.button(
        "Generate PDF Report",
        use_container_width=True
    ):
        try:
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

            st.session_state["sentinel_pdf_report"] = pdf_data

            st.success("PDF report generated successfully!")

        except Exception as e:
            st.error(f"Unable to generate PDF report: {e}")

    # Display download button after PDF generation
    if "sentinel_pdf_report" in st.session_state:

        st.download_button(
            label="Download Security Report (PDF)",
            data=st.session_state["sentinel_pdf_report"],
            file_name=(
                "sentinel_soc_report_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            ),
            mime="application/pdf",
            use_container_width=True
        )