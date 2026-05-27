"""
reports/report_generator.py
---------------------------
Phase 6 — Audit report generation.
"""

import os
import pandas as pd
from datetime import datetime
from config import settings

def generate_report():
    print("[SFTMS] Generating audit report...")
    
    if not os.path.exists(settings.LOG_FILE):
        print(f"[SFTMS] No log file found at {settings.LOG_FILE}. Cannot generate report without logs.")
        return
        
    try:
        log_df = pd.read_csv(settings.LOG_FILE)
    except Exception as e:
        print(f"[SFTMS] Failed to read {settings.LOG_FILE}: {e}")
        return

    violations_df = None
    if os.path.exists(settings.VIOLATIONS_FILE):
        try:
            violations_df = pd.read_csv(settings.VIOLATIONS_FILE)
        except Exception as e:
            print(f"[SFTMS] Failed to read {settings.VIOLATIONS_FILE}: {e}")

    # Process stats
    total_events = len(log_df)
    events_by_type = log_df['event_type'].value_counts().to_dict() if 'event_type' in log_df else {}
    top_users = log_df['username'].value_counts().head(10).to_dict() if 'username' in log_df else {}
    
    # Format summary stats
    summary_data = []
    summary_data.append({"Metric": "Total events", "Value": total_events})
    
    for evt_type, count in events_by_type.items():
        summary_data.append({"Metric": f"Events: {evt_type}", "Value": count})
        
    if violations_df is not None and not violations_df.empty:
        total_violations = len(violations_df)
        summary_data.append({"Metric": "Total violations", "Value": total_violations})
        if 'severity' in violations_df:
            for sev, count in violations_df['severity'].value_counts().items():
                summary_data.append({"Metric": f"Violations: {sev}", "Value": count})
    else:
        summary_data.append({"Metric": "Total violations", "Value": 0})
        
    if 'integrity_ok' in log_df:
        integrity_failures = len(log_df[log_df['integrity_ok'] == False])
        summary_data.append({"Metric": "Integrity failures", "Value": integrity_failures})
        
    summary_df = pd.DataFrame(summary_data)
    
    top_users_df = pd.DataFrame(list(top_users.items()), columns=["Username", "Event Count"])

    # Hourly activity
    hourly_df = None
    if 'timestamp' in log_df:
        try:
            # We copy and convert the timestamp column to avoid warnings
            log_df['timestamp_dt'] = pd.to_datetime(log_df['timestamp'])
            hourly_counts = log_df['timestamp_dt'].dt.hour.value_counts().sort_index()
            hourly_df = pd.DataFrame({'Hour': hourly_counts.index, 'Event Count': hourly_counts.values})
            # Format Hour to a 24-hour string representation
            hourly_df['Hour'] = hourly_df['Hour'].apply(lambda x: f"{x:02d}:00")
            log_df.drop(columns=['timestamp_dt'], inplace=True)
        except Exception as e:
            print(f"[SFTMS] Could not process hourly activity: {e}")

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(settings.REPORTS_DIR, f"audit_report_{timestamp_str}.xlsx")
    
    try:
        with pd.ExcelWriter(report_file, engine='openpyxl') as writer:
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            top_users_df.to_excel(writer, sheet_name='Top Users', index=False)
            if hourly_df is not None:
                hourly_df.to_excel(writer, sheet_name='Hourly Activity', index=False)
            log_df.to_excel(writer, sheet_name='Full Log', index=False)
            if violations_df is not None and not violations_df.empty:
                violations_df.to_excel(writer, sheet_name='Violations', index=False)
                
        print(f"[SFTMS] ✓ Report successfully generated: {report_file}")
    except Exception as e:
        print(f"[SFTMS] ✗ Failed to write Excel report: {e}")

if __name__ == "__main__":
    generate_report()
