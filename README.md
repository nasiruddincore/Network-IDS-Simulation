# 🛡️ Cybersecurity Awareness & Threat Intelligence Dashboard

![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Framework-FF4B4B)
![Security](https://img.shields.io/badge/Security-Defensive-purple)
![License](https://img.shields.io/badge/License-MIT-green)

A unified, defensive cybersecurity platform bridging the gap between technical threat analysis and human-centric security hygiene. This dashboard ingests synthetic threat-intel feeds, normalizes and enriches Indicators of Compromise (IOCs), calculates organizational risk, and delivers interactive security awareness training to end-users.

---

## 📋 Table of Contents
1. [Overview & Cybersecurity Relevance](#-overview--cybersecurity-relevance)
2. [Problem Statement](#-problem-statement)
3. [System Objectives](#-system-objectives)
4. [Architecture & Data Flow](#-architecture--data-flow)
5. [Core Features](#-core-features)
6. [Key Security Concepts](#-key-security-concepts)
7. [Folder Structure](#-folder-structure)
8. [Installation & Setup](#-installation--setup)
9. [Usage Guide](#-usage-guide)
10. [Future Improvements](#-future-improvements)
11. [Ethical Disclaimer](#-ethical-disclaimer)

---

## 📌 Overview & Cybersecurity Relevance
Modern Security Operations Centers (SOCs) blend external threat intelligence with internal telemetry for faster detection and better hygiene. However, technical defenses often fail when users cannot recognize social engineering or phishing attempts. This project acts as a centralized ingest engine for synthetic threat indicators (IPs, domains, hashes, CVEs) while simultaneously operating a Security Awareness Center. Pairing actionable IOC analysis with awareness nudges reduces phishing clicks, patch delays, and incident response times.

---

## ⚠️ Problem Statement
* **Alert Fatigue:** SOC analysts are overwhelmed by raw indicators without context, risk prioritization, or confidence scoring.
* **Human Vulnerability:** The strongest firewall cannot prevent a user from willingly handing over credentials to a phishing site.
* **Disconnected Systems:** Threat intelligence (technical) and security awareness (human) are traditionally siloed, preventing a unified defensive posture.

---

## 🎯 System Objectives
1. **Threat Intelligence Feed & IOC Dashboard:** Collect, categorize, and visualize defensive threat intelligence.
2. **Threat Severity Scoring:** Distinguish between the potential impact of a threat (Risk) and the reliability of the intelligence (Confidence).
3. **SOC-Style Investigation View:** Provide analysts with actionable mitigation steps and MITRE ATT&CK mapping.
4. **Awareness Learning Center:** Deliver security quizzes, calculate awareness scores, and provide incident-awareness guidance[cite: 1].

---

## 📐 Architecture & Data Flow

```text
Synthetic Threat Data ──► Data Ingestion ──► IOC Validation & Normalization
                                                    │
                                                    ▼
[ SOC Analyst Dashboard ] ◄── Alert Engine ◄── Risk & Confidence Engine
        │                                           │
        ▼                                           ▼
 Threat Investigation                        MITRE ATT&CK Mapping

============================= PARALLEL ===============================

[ End User ] ──► Awareness Center ──► Quizzes ──► Awareness Score
