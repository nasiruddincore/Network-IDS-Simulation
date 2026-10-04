def extract_network_features(flow):
    """Calculates derived features for detection engines."""
    duration = max(flow['duration_seconds'], 0.001)  # Prevent division by zero
    features = {
        'bytes_per_second': flow['byte_count'] / duration,
        'packets_per_second': flow['packet_count'] / duration,
        'failure_ratio': flow['failed_connection_count'] / max(flow['connection_count'], 1),
        'syn_ratio': flow['syn_count'] / max(flow['packet_count'], 1)
    }
    return features

def signature_detection(flow, features):
    """Rule-based detection for known statistical patterns."""
    alerts = []
    
    if flow['connection_count'] > 100 and features['packets_per_second'] > 50:
        alerts.append({"rule_id": "SIG-001", "name": "High Connection Rate", "severity": "HIGH", "score": 75})
        
    if features['failure_ratio'] > 0.7 and flow['connection_count'] > 20:
        alerts.append({"rule_id": "SIG-002", "name": "Repeated Failed Connections", "severity": "MEDIUM", "score": 65})
        
    if features['syn_ratio'] > 0.8 and flow['packet_count'] > 50:
        alerts.append({"rule_id": "SIG-003", "name": "SYN-Heavy Connection Behavior", "severity": "HIGH", "score": 85})
        
    if flow['byte_count'] > 5000000:
        alerts.append({"rule_id": "SIG-004", "name": "Abnormally High Traffic Volume", "severity": "MEDIUM", "score": 60})
        
    return alerts

def anomaly_detection(flow, features):
    """Statistical anomaly detection comparing against hardcoded safe baselines for simulation."""
    anomaly_score = 0
    reasons = []
    
    # Baseline: Normal web traffic is usually < 1000 pkts/sec
    if features['packets_per_second'] > 2000:
        anomaly_score += 40
        reasons.append("Extreme packet rate deviation")
        
    # Baseline: Normal connections rarely fail 50% of the time
    if features['failure_ratio'] > 0.5:
        anomaly_score += 30
        reasons.append("High connection failure deviation")
        
    return min(anomaly_score, 100), reasons

def calculate_risk_score(flow):
    """Hybrid Risk Engine combining Signatures and Anomalies."""
    features = extract_network_features(flow)
    
    sig_alerts = signature_detection(flow, features)
    anomaly_score, anomaly_reasons = anomaly_detection(flow, features)
    
    # Weights: 60% Signature, 40% Anomaly
    highest_sig_score = max([a['score'] for a in sig_alerts]) if sig_alerts else 0
    final_risk = int((highest_sig_score * 0.6) + (anomaly_score * 0.4))
    
    classification = "NORMAL"
    if final_risk > 20: classification = "LOW RISK"
    if final_risk > 40: classification = "SUSPICIOUS"
    if final_risk > 60: classification = "HIGH RISK"
    if final_risk > 80: classification = "CRITICAL"
    
    return {
        "risk_score": final_risk,
        "classification": classification,
        "signatures_triggered": [a['name'] for a in sig_alerts],
        "anomaly_reasons": anomaly_reasons,
        "features": features
    }