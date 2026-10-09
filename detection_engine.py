import pandas as pd
from database import get_connection


def create_alert(alert_type, description, severity,
                 username, ip_address, timestamp):

    connection = get_connection()

    if connection is None:
        return False

    try:
        cursor = connection.cursor()

        query = """
            INSERT INTO alerts
            (alert_type, description, severity, username,
             ip_address, timestamp, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        values = (
            alert_type,
            description,
            severity,
            username,
            ip_address,
            timestamp,
            "Open"
        )

        cursor.execute(query, values)
        connection.commit()

        cursor.close()
        connection.close()

        return True

    except Exception as e:
        print("Error creating alert:", e)
        return False


def detect_brute_force(df):
    """
    Detect 5 or more failed login attempts
    from the same IP within 10 minutes.
    """

    alerts_created = 0

    failed = df[df["status"].str.lower() == "failed"].copy()

    if failed.empty:
        return 0

    failed["timestamp"] = pd.to_datetime(failed["timestamp"])

    for ip in failed["ip_address"].unique():

        ip_logs = failed[failed["ip_address"] == ip]
        ip_logs = ip_logs.sort_values("timestamp")

        for i in range(len(ip_logs)):

            start_time = ip_logs.iloc[i]["timestamp"]
            end_time = start_time + pd.Timedelta(minutes=10)

            window = ip_logs[
                (ip_logs["timestamp"] >= start_time) &
                (ip_logs["timestamp"] <= end_time)
            ]

            if len(window) >= 5:

                username = window.iloc[0]["username"]

                description = (
                    f"{len(window)} failed login attempts "
                    f"detected from IP {ip} within 10 minutes."
                )

                created = create_alert(
                    "Brute Force Attack",
                    description,
                    "High",
                    username,
                    ip,
                    start_time.strftime("%Y-%m-%d %H:%M:%S")
                )

                if created:
                    alerts_created += 1

                break

    return alerts_created


def detect_repeated_failed_logins(df):
    """
    Detect 5 or more failed login attempts
    against the same username.
    """

    alerts_created = 0

    failed = df[
        df["status"].str.lower() == "failed"
    ].copy()

    if failed.empty:
        return 0

    counts = failed.groupby("username").size()

    for username, count in counts.items():

        if count >= 5:

            user_logs = failed[
                failed["username"] == username
            ]

            ip = user_logs.iloc[0]["ip_address"]
            timestamp = user_logs.iloc[-1]["timestamp"]

            description = (
                f"User '{username}' experienced "
                f"{count} failed login attempts."
            )

            created = create_alert(
                "Repeated Failed Login",
                description,
                "Medium",
                username,
                ip,
                str(timestamp)
            )

            if created:
                alerts_created += 1

    return alerts_created


def detect_success_after_failures(df):
    """
    Detect a successful login shortly after
    multiple failed attempts from the same IP.
    """

    alerts_created = 0

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    for ip in df["ip_address"].unique():

        ip_logs = df[
            df["ip_address"] == ip
        ].sort_values("timestamp")

        for i in range(len(ip_logs)):

            current = ip_logs.iloc[i]

            if str(current["status"]).lower() != "success":
                continue

            success_time = current["timestamp"]

            previous_logs = ip_logs[
                (ip_logs["timestamp"] < success_time) &
                (
                    ip_logs["timestamp"] >=
                    success_time - pd.Timedelta(minutes=10)
                ) &
                (
                    ip_logs["status"].str.lower() == "failed"
                )
            ]

            if len(previous_logs) >= 3:

                description = (
                    f"Successful login detected after "
                    f"{len(previous_logs)} failed attempts."
                )

                created = create_alert(
                    "Possible Account Compromise",
                    description,
                    "High",
                    current["username"],
                    ip,
                    success_time.strftime("%Y-%m-%d %H:%M:%S")
                )

                if created:
                    alerts_created += 1

                break

    return alerts_created


def detect_unusual_login_time(df):
    """
    Detect successful logins between 11 PM and 6 AM.
    """

    alerts_created = 0

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    successful = df[
        df["status"].str.lower() == "success"
    ]

    for _, row in successful.iterrows():

        hour = row["timestamp"].hour

        if hour >= 23 or hour < 6:

            description = (
                f"Successful login occurred at "
                f"{row['timestamp'].strftime('%H:%M:%S')}, "
                f"outside normal login hours."
            )

            created = create_alert(
                "Unusual Login Time",
                description,
                "Medium",
                row["username"],
                row["ip_address"],
                row["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            )

            if created:
                alerts_created += 1

    return alerts_created


def run_detection(df):

    total_alerts = 0

    total_alerts += detect_brute_force(df)
    total_alerts += detect_repeated_failed_logins(df)
    total_alerts += detect_success_after_failures(df)
    total_alerts += detect_unusual_login_time(df)

    return total_alerts