import requests
import json
import time
import random
from datetime import datetime

API_URL = "http://localhost:8000/api/ingest"

IPS = ["192.168.1.5", "10.0.0.2", "45.33.22.11", "185.22.1.4 (Malicious)"]
USERS = ["admin", "root", "user1", "guest"]

def generate_log():
    # 5% chance of malicious attack
    is_attack = random.random() < 0.2
    
    log = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": random.choice(IPS),
        "destination_ip": "192.168.1.100",
        "protocol": "TCP",
        "severity": "INFO",
        "message": "Connection established",
        "event_id": 100
    }
    
    if is_attack:
        attack_type = random.choice(["brute", "sql", "scan"])
        
        if attack_type == "brute":
            log["message"] = f"User Login Failed for {random.choice(USERS)}"
            log["severity"] = "HIGH"
            log["event_id"] = 4625 # Windows failure
            
        elif attack_type == "sql":
            log["message"] = "GET /search?q=UNION SELECT * FROM users"
            log["severity"] = "CRITICAL"
            log["protocol"] = "HTTP"
            
    return log

print(f"[*] Starting Log Simulator targeting {API_URL}...")
print("[*] Press Ctrl+C to stop.")

while True:
    try:
        log_data = generate_log()
        response = requests.post(API_URL, json=log_data)
        print(f"Sent: {log_data['message']} | Status: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")
        print("Is the backend running?")
    
    time.sleep(random.uniform(0.1, 1.0))
