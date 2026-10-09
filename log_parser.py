import pandas as pd
from database import insert_log
from detection_engine import run_detection

REQUIRED_COLUMNS = [
    "timestamp",
    "username",
    "ip_address",
    "status",
    "event_type"
]


def parse_log_file(file_path):

    try:
        df = pd.read_csv(file_path)

        # Check required columns
        missing_columns = [
            column for column in REQUIRED_COLUMNS
            if column not in df.columns
        ]

        if missing_columns:
            raise ValueError(
                f"Missing columns: {', '.join(missing_columns)}"
            )

        # Keep required columns
        df = df[REQUIRED_COLUMNS].copy()

        # Convert timestamp
        df["timestamp"] = pd.to_datetime(
            df["timestamp"],
            errors="coerce"
        )

        # Remove invalid rows
        df = df.dropna(
            subset=[
                "timestamp",
                "username",
                "ip_address",
                "status",
                "event_type"
            ]
        )

        # Clean text
        df["username"] = df["username"].astype(str).str.strip()
        df["ip_address"] = df["ip_address"].astype(str).str.strip()
        df["status"] = df["status"].astype(str).str.strip()
        df["event_type"] = df["event_type"].astype(str).str.strip()

        return df

    except Exception as e:
        print("Error parsing log file:", e)
        return None


def save_logs_to_database(df):

    successful = 0

    for _, row in df.iterrows():

        result = insert_log(
            row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            row["username"],
            row["ip_address"],
            row["status"],
            row["event_type"]
        )

        if result:
            successful += 1

    return successful


if __name__ == "__main__":
    df = parse_log_file("sample_logs.csv")

    if df is not None:
        print("\nLog file parsed successfully!")
        print("Total logs:", len(df))

        inserted = save_logs_to_database(df)

        print(f"{inserted} logs inserted into MySQL successfully!")

        alerts = run_detection(df)

        print(f"{alerts} security alerts generated!")