import pandas as pd
import random
import os
from datetime import datetime, timedelta

def generate_synthetic_traffic(num_records=5000):
    os.makedirs(os.path.join(os.path.dirname(__file__), "..", "data"), exist_ok=True)
    
    scenarios = [
        "NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", 
        "HIGH_CONNECTION_RATE", "REPEATED_FAILED_CONNECTIONS", 
        "MULTI_PORT_PROBING_PATTERN", "SYN_HEAVY_PATTERN", "HIGH_TRAFFIC_VOLUME"
    ]
    
    safe_ips = [f"192.0.2.{i}" for i in range(1, 50)] + [f"198.51.100.{i}" for i in range(1, 50)]
    
    data = []
    current_time = datetime.now() - timedelta(days=1)
    
    for i in range(num_records):
        scenario = random.choices(scenarios, weights=[0.4, 0.2, 0.1, 0.05, 0.05, 0.05, 0.05, 0.1])[0]
        
        src_ip = random.choice(safe_ips)
        dst_ip = random.choice(safe_ips)
        protocol = random.choice(["TCP", "UDP"])
        
        # Default normal baselines
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 22])
        pkt_count = random.randint(5, 50)
        byte_count = pkt_count * random.randint(64, 1500)
        duration = round(random.uniform(0.1, 5.0), 2)
        conn_count = random.randint(1, 5)
        failed_conn = 0
        syn_count = random.randint(1, 3)
        rst_count = 0
        label = "NORMAL"
        
        # Inject Synthetic Scenarios
        if scenario == "HIGH_CONNECTION_RATE":
            conn_count = random.randint(100, 500)
            duration = round(random.uniform(0.1, 1.0), 2)
            label = "SUSPICIOUS"
        elif scenario == "REPEATED_FAILED_CONNECTIONS":
            conn_count = random.randint(20, 50)
            failed_conn = random.randint(15, 45)
            label = "SUSPICIOUS"
        elif scenario == "MULTI_PORT_PROBING_PATTERN":
            dst_port = random.randint(1, 1024)
            conn_count = random.randint(50, 200)
            failed_conn = conn_count - random.randint(0, 5)
            label = "SUSPICIOUS"
        elif scenario == "SYN_HEAVY_PATTERN":
            syn_count = random.randint(100, 1000)
            pkt_count = syn_count + random.randint(0, 10)
            label = "SUSPICIOUS"
        elif scenario == "HIGH_TRAFFIC_VOLUME":
            byte_count = random.randint(10000000, 50000000)
            pkt_count = random.randint(10000, 50000)
            label = "SUSPICIOUS"

        avg_pkt_size = round(byte_count / pkt_count, 2) if pkt_count > 0 else 0
        current_time += timedelta(seconds=random.uniform(0.1, 2.0))

        data.append({
            "flow_id": f"FLW-{10000+i}",
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_count": pkt_count,
            "byte_count": byte_count,
            "duration_seconds": duration,
            "connection_count": conn_count,
            "failed_connection_count": failed_conn,
            "syn_count": syn_count,
            "rst_count": rst_count,
            "average_packet_size": avg_pkt_size,
            "label": label,
            "scenario_type": scenario
        })
        
    df = pd.DataFrame(data)
    out_path = os.path.join(os.path.dirname(__file__), "..", "data", "network_traffic.csv")
    df.to_csv(out_path, index=False)
    print(f"[SUCCESS] Generated {num_records} flow records at {out_path}")

if __name__ == "__main__":
    generate_synthetic_traffic()