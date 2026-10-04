import streamlit as st
import pandas as pd
import sqlite3
import os
import time
import plotly.express as px
from ids.engine import calculate_risk_score

# --- 1. CONFIG & DB SETUP ---
st.set_page_config(page_title="SOC Network IDS", page_icon="🛡️", layout="wide")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "security_events.db")
DATA_PATH = os.path.join(BASE_DIR, "data", "network_traffic.csv")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY, timestamp TEXT, source_ip TEXT, 
                    destination_ip TEXT, protocol TEXT, rule_matched TEXT, 
                    severity TEXT, risk_score INTEGER, status TEXT, analyst_notes TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- 2. TRAFFIC SIMULATOR PIPELINE ---
@st.cache_data
def load_traffic_data():
    if not os.path.exists(DATA_PATH):
        st.error("Synthetic dataset not found. Please run simulator/generate_dataset.py first.")
        return pd.DataFrame()
    return pd.read_csv(DATA_PATH)

def process_flows(df, batch_size=50):
    """Simulates real-time ingestion by processing a batch of flows."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    sample_df = df.sample(batch_size)
    for _, flow in sample_df.iterrows():
        analysis = calculate_risk_score(flow)
        
        if analysis['risk_score'] > 40: # Generate alert for Suspicious+
            alert_id = f"ALT-{int(time.time() * 1000)}-{flow['flow_id']}"
            rule_matched = ", ".join(analysis['signatures_triggered'] + analysis['anomaly_reasons'])
            
            c.execute("INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (alert_id, flow['timestamp'], flow['source_ip'], flow['destination_ip'],
                       flow['protocol'], rule_matched, analysis['classification'], 
                       analysis['risk_score'], "NEW", ""))
    conn.commit()
    conn.close()

# --- 3. UI DASHBOARD ---
df_traffic = load_traffic_data()
st.sidebar.title("🛡️ SOC Control Panel")
menu = st.sidebar.radio("Navigation", ["Dashboard Overview", "Alert Investigation", "Network Analytics"])

if st.sidebar.button("▶️ Simulate Live Traffic Batch"):
    if not df_traffic.empty:
        process_flows(df_traffic)
        st.sidebar.success("Processed 50 flow records. Dashboard updated.")

# Fetch Live Alerts
conn = sqlite3.connect(DB_PATH)
df_alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
conn.close()

if menu == "Dashboard Overview":
    st.header("Security Operations Center (SOC) Dashboard")
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Network Flows Analyzed", len(df_traffic))
    col2.metric("Open Alerts", len(df_alerts[df_alerts['status'] == 'NEW']) if not df_alerts.empty else 0)
    col3.metric("Critical Investigations", len(df_alerts[df_alerts['severity'] == 'CRITICAL']) if not df_alerts.empty else 0)
    col4.metric("Average Risk Score", f"{df_alerts['risk_score'].mean():.1f}" if not df_alerts.empty else "0")

    if not df_alerts.empty:
        st.subheader("Recent Security Alerts")
        st.dataframe(df_alerts[['timestamp', 'source_ip', 'destination_ip', 'rule_matched', 'severity', 'risk_score', 'status']].head(10), use_container_width=True)

        c1, c2 = st.columns(2)
        with c1:
            fig1 = px.pie(df_alerts, names='severity', title='Alerts by Severity', hole=0.4)
            st.plotly_chart(fig1, use_container_width=True)
        with c2:
            fig2 = px.bar(df_alerts['rule_matched'].value_counts().reset_index(), x='rule_matched', y='count', title='Top Triggered Rules')
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No alerts generated yet. Click 'Simulate Live Traffic Batch' to ingest data.")

elif menu == "Alert Investigation":
    st.header("Incident Management & Triage")
    if not df_alerts.empty:
        selected_alert = st.selectbox("Select Alert to Investigate:", df_alerts['alert_id'].tolist())
        alert_data = df_alerts[df_alerts['alert_id'] == selected_alert].iloc[0]
        
        st.subheader("Event Context")
        c1, c2, c3, c4 = st.columns(4)
        c1.write(f"**Source IP:** {alert_data['source_ip']}")
        c2.write(f"**Destination IP:** {alert_data['destination_ip']}")
        c3.write(f"**Risk Score:** {alert_data['risk_score']}/100")
        c4.write(f"**Current Status:** {alert_data['status']}")
        
        st.error(f"**Detection Reason:** {alert_data['rule_matched']}")
        
        st.subheader("Analyst Actions")
        new_status = st.radio("Update Status:", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"], index=["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].index(alert_data['status']))
        notes = st.text_area("Analyst Notes:", value=alert_data['analyst_notes'])
        
        if st.button("Save Incident Record"):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE alerts SET status = ?, analyst_notes = ? WHERE alert_id = ?", (new_status, notes, selected_alert))
            conn.commit()
            conn.close()
            st.success("Incident updated successfully. Refreshing...")
            st.rerun()
    else:
        st.info("Alert queue is empty.")

elif menu == "Network Analytics":
    st.header("Synthetic Network Traffic Telemetry")
    if not df_traffic.empty:
        c1, c2 = st.columns(2)
        with c1:
            fig1 = px.histogram(df_traffic, x="scenario_type", title="Synthetic Scenario Distribution", color="label")
            st.plotly_chart(fig1, use_container_width=True)
        with c2:
            fig2 = px.scatter(df_traffic, x="duration_seconds", y="packet_count", color="label", title="Duration vs Packet Count Anomaly Scatter")
            st.plotly_chart(fig2, use_container_width=True)