# Network Intrusion Detection System (IDS) Simulation

## Overview
A defensive cybersecurity project simulating a Network Intrusion Detection System (NIDS). This platform ingests synthetic network traffic, applies signature and statistical anomaly-based detection rules, calculates hybrid risk scores, and routes alerts to a Tier-1 SOC Dashboard for incident triage.

## Cybersecurity Relevance
Modern Security Operations Centers (SOCs) utilize IDS technology to detect unauthorized scanning, data exfiltration, and denial-of-service patterns. This project mirrors enterprise detection workflows (ingestion → extraction → detection → triage) while adhering to strict defensive ethical standards by using 100% synthetic data.

## Technology Stack
* **Language:** Python
* **Frontend/Backend:** Streamlit
* **Data Processing:** Pandas, Numpy
* **Database:** SQLite
* **Visualizations:** Plotly

## IDS Concepts Demonstrated
* **Signature-Based Detection:** Identifies known suspicious patterns (e.g., highly specific port scans or SYN floods). Fast and explainable, but misses novel behaviors.
* **Anomaly-Based Detection:** Establishes a baseline (e.g., normal packets/second) and flags deviations. Identifies unknown patterns but can yield false positives.
* **Hybrid Risk Scoring:** Combines both methods to ensure high-fidelity alerting, reducing SOC alert fatigue.
* **Alert Correlation:** Aggregates related anomalies into a unified risk score.

## Installation & Usage
1. **Initialize Workspace:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt