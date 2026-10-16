import pandas as pd
import streamlit as st
from database import get_logs, get_alerts

def load_logs():
    try:
        data = get_logs()
        return pd.DataFrame(data) if data else pd.DataFrame()
    except Exception as exc:
        st.error(f"Could not load logs from MySQL: {exc}")
        return pd.DataFrame()

def load_alerts():
    try:
        data = get_alerts()
        return pd.DataFrame(data) if data else pd.DataFrame()
    except Exception as exc:
        st.error(f"Could not load alerts from MySQL: {exc}")
        return pd.DataFrame()

def normalize_timestamp(df, column="timestamp"):
    if not df.empty and column in df.columns:
        df[column] = pd.to_datetime(df[column], errors="coerce")
    return df
