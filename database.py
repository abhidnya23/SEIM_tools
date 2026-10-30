import os
import mysql.connector
from mysql.connector import Error


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_connection():
    try:
        db_host = os.getenv("DB_HOST", "localhost")
        db_user = os.getenv("DB_USER", "root")
        db_password = os.getenv("DB_PASSWORD", "root")
        db_name = os.getenv("DB_NAME", "siem_db")
        db_port = int(os.getenv("DB_PORT", 3306))

        connection_config = {
            "host": db_host,
            "user": db_user,
            "password": db_password,
            "database": db_name,
            "port": db_port,
            "connection_timeout": 10
        }

        # Optional SSL certificate for cloud MySQL
        ssl_ca = os.getenv("DB_SSL_CA")

        if ssl_ca:
            connection_config["ssl_ca"] = ssl_ca
            connection_config["ssl_verify_cert"] = True

        connection = mysql.connector.connect(**connection_config)

        return connection

    except Error as e:
        print("Database connection error:", e)
        return None

    except ValueError as e:
        print("Invalid database configuration:", e)
        return None


# ==========================================
# INSERT LOG
# ==========================================

def insert_log(timestamp, username, ip_address, status, event_type):

    connection = get_connection()

    if connection is None:
        return False

    cursor = None

    try:
        cursor = connection.cursor()

        query = """
            INSERT INTO logs
            (timestamp, username, ip_address, status, event_type)
            VALUES (%s, %s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (timestamp, username, ip_address, status, event_type)
        )

        connection.commit()

        return True

    except Error as e:
        print("Error inserting log:", e)
        return False

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()


# ==========================================
# GET LOGS
# ==========================================

def get_logs():

    connection = get_connection()

    if connection is None:
        print("Could not connect to database.")
        return []

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                timestamp,
                username,
                ip_address,
                status,
                event_type
            FROM logs
            ORDER BY timestamp DESC
        """)

        logs = cursor.fetchall()

        print("Logs retrieved:", len(logs))

        return logs

    except Error as e:
        print("Error retrieving logs:", e)
        return []

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()


# ==========================================
# GET ALERTS
# ==========================================

def get_alerts():

    connection = get_connection()

    if connection is None:
        return []

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC
        """)

        alerts = cursor.fetchall()

        return alerts

    except Error as e:
        print("Error retrieving alerts:", e)
        return []

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()


# ==========================================
# GET LOG COUNT
# ==========================================

def get_log_count():

    connection = get_connection()

    if connection is None:
        return 0

    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM logs")

        count = cursor.fetchone()[0]

        return count

    except Error as e:
        print("Error getting log count:", e)
        return 0

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()


# ==========================================
# GET ALERT COUNT
# ==========================================

def get_alert_count():

    connection = get_connection()

    if connection is None:
        return 0

    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM alerts")

        count = cursor.fetchone()[0]

        return count

    except Error as e:
        print("Error getting alert count:", e)
        return 0

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()


# ==========================================
# GET HIGH ALERT COUNT
# ==========================================

def get_high_alert_count():

    connection = get_connection()

    if connection is None:
        return 0

    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE LOWER(severity) = 'high'
        """)

        count = cursor.fetchone()[0]

        return count

    except Error as e:
        print("Error getting high alert count:", e)
        return 0

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()


# ==========================================
# GET CRITICAL ALERT COUNT
# ==========================================

def get_critical_alert_count():

    connection = get_connection()

    if connection is None:
        return 0

    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE LOWER(severity) = 'critical'
        """)

        count = cursor.fetchone()[0]

        return count

    except Error as e:
        print("Error getting critical alert count:", e)
        return 0

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()


# ==========================================
# GET ALERT STATUS COUNTS
# ==========================================

def get_alert_status_counts():

    connection = get_connection()

    if connection is None:
        return {}

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT status, COUNT(*) AS total
            FROM alerts
            GROUP BY status
        """)

        results = cursor.fetchall()

        return {
            str(row["status"] or "NEW").upper(): row["total"]
            for row in results
        }

    except Error as e:
        print("Error getting alert status counts:", e)
        return {}

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()


# ==========================================
# UPDATE ALERT STATUS
# ==========================================

def update_alert_status(alert_id, status, notes):

    connection = get_connection()

    if connection is None:
        return False

    cursor = None

    try:
        cursor = connection.cursor()

        query = """
            UPDATE alerts
            SET status = %s,
                investigation_notes = %s
            WHERE id = %s
        """

        cursor.execute(query, (status, notes, alert_id))

        connection.commit()

        return cursor.rowcount > 0

    except Error as e:
        print("Error updating alert:", e)
        return False

    finally:
        if cursor is not None:
            cursor.close()

        if connection.is_connected():
            connection.close()
