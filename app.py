"""
app.py
------
Streamlit Web Dashboard for the Secure File Transfer Monitoring System (SFTMS).
This serves as the frontend for the monitoring system and allows you to
deploy the project to Streamlit Community Cloud to get a live URL.
"""

import streamlit as st
import pandas as pd
import os

# --- Page Config ---
st.set_page_config(
    page_title="SFTMS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Secure File Transfer Monitoring System")
st.markdown("""
Welcome to the SFTMS Security Dashboard. This interface provides real-time visibility into 
file system events, unauthorized transfers, and integrity violations.
""")

# --- Load Data ---
LOG_FILE = os.path.join("data", "transfer_log.csv")
VIOLATIONS_FILE = os.path.join("data", "violations.csv")

@st.cache_data
def load_data(filepath):
    if os.path.exists(filepath):
        try:
            df = pd.read_csv(filepath)
            # Ensure timestamp is parsed properly if it exists
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            return df
        except Exception as e:
            st.error(f"Error loading {filepath}: {e}")
            return pd.DataFrame()
    else:
        return pd.DataFrame()

df_logs = load_data(LOG_FILE)
df_violations = load_data(VIOLATIONS_FILE)

if df_logs.empty:
    st.warning("No transfer logs found! Please run the local watcher to generate data before viewing the dashboard.")
    st.stop()

# --- Metrics ---
st.subheader("📊 Quick Statistics")
col1, col2, col3, col4 = st.columns(4)

total_events = len(df_logs)
total_violations = len(df_violations)
violation_rate = f"{(total_violations/total_events)*100:.1f}%" if total_events > 0 else "0%"
critical_alerts = len(df_violations[df_violations['severity'] == 'CRITICAL']) if not df_violations.empty and 'severity' in df_violations else 0

col1.metric("Total File Events", total_events)
col2.metric("Total Violations Flagged", total_violations, delta_color="inverse")
col3.metric("Violation Rate", violation_rate)
col4.metric("Critical Alerts", critical_alerts, delta="-1" if critical_alerts==0 else str(critical_alerts), delta_color="inverse")

st.divider()

# --- Layout: Charts & Tables ---
colA, colB = st.columns(2)

with colA:
    st.subheader("Events by Category")
    if 'transfer_category' in df_logs.columns:
        cat_counts = df_logs['transfer_category'].value_counts().reset_index()
        cat_counts.columns = ['Category', 'Count']
        st.bar_chart(cat_counts, x='Category', y='Count', color="#3b82f6")
    else:
        st.info("No category data available.")

with colB:
    st.subheader("Violations by Severity")
    if not df_violations.empty and 'severity' in df_violations.columns:
        sev_counts = df_violations['severity'].value_counts().reset_index()
        sev_counts.columns = ['Severity', 'Count']
        st.bar_chart(sev_counts, x='Severity', y='Count', color="#ef4444")
    else:
        st.info("No violations recorded! System is secure.")

st.divider()

# --- Detailed Data Views ---
st.subheader("📋 Recent File Events")
# Show the most recent 50 events
st.dataframe(
    df_logs.sort_values(by='timestamp', ascending=False).head(50) if 'timestamp' in df_logs.columns else df_logs.head(50),
    use_container_width=True
)

if not df_violations.empty:
    st.subheader("🚨 Security Violations Log")
    st.dataframe(
        df_violations.style.applymap(
            lambda x: 'background-color: #fee2e2; color: #991b1b' if x == 'CRITICAL' 
                      else 'background-color: #fef3c7; color: #92400e' if x == 'HIGH'
                      else 'background-color: #dbeafe; color: #1e40af' if x == 'MEDIUM'
                      else '',
            subset=['severity']
        ) if 'severity' in df_violations.columns else df_violations,
        use_container_width=True
    )
