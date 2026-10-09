import mysql.connector
from mysql.connector import Error


def get_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="siem_db"
        )

        return connection

    except Error as e:
        print("Database connection error:", e)
        return None


def insert_log(timestamp, username, ip_address, status, event_type):
    connection = get_connection()

    if connection is None:
        return False

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

        cursor.close()
        connection.close()

        return True

    except Error as e:
        print("Error inserting log:", e)

        if connection:
            connection.close()

        return False

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

        if connection is not None and connection.is_connected():
            connection.close()

def get_alerts():
    connection = get_connection()

    if connection is None:
        return []

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC
        """)

        alerts = cursor.fetchall()

        cursor.close()
        connection.close()

        return alerts

    except Error as e:
        print("Error retrieving alerts:", e)
        return []


def get_log_count():
    connection = get_connection()

    if connection is None:
        return 0

    try:
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM logs")

        count = cursor.fetchone()[0]

        cursor.close()
        connection.close()

        return count

    except Error as e:
        print("Error getting log count:", e)
        return 0


def get_alert_count():
    connection = get_connection()

    if connection is None:
        return 0

    try:
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM alerts")

        count = cursor.fetchone()[0]

        cursor.close()
        connection.close()

        return count

    except Error as e:
        print("Error getting alert count:", e)
        return 0


def get_high_alert_count():
    connection = get_connection()

    if connection is None:
        return 0

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE LOWER(severity) = 'high'
        """)

        count = cursor.fetchone()[0]

        cursor.close()
        connection.close()

        return count

    except Error as e:
        print("Error getting high alert count:", e)
        return 0


def get_critical_alert_count():
    connection = get_connection()

    if connection is None:
        return 0

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE LOWER(severity) = 'critical'
        """)

        count = cursor.fetchone()[0]

        cursor.close()
        connection.close()

        return count

    except Error as e:
        print("Error getting critical alert count:", e)
        return 0