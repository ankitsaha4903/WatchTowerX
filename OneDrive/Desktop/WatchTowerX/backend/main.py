import os
import sqlite3
import json
import asyncio
from datetime import datetime
from typing import List, Optional
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import pandas as pd

app = FastAPI(title="WatchTowerX Platform", version="2.2.0")

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc_logs.db")
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")

# --- DATABASE SETUP (Persistence) ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  source_ip TEXT, 
                  destination_ip TEXT, 
                  protocol TEXT, 
                  severity TEXT, 
                  message TEXT, 
                  event_id INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS threats 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  source_ip TEXT, 
                  type TEXT, 
                  severity TEXT, 
                  score INTEGER,
                  mitre_id TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- THREAT INTEL MOCK (Engineering Feature) ---
# In a real SOC, this pulls from VirusTotal or AlienVault OTX
THREAT_INTEL_FEED = {
    "185.22.1.4": "APT29_C2_Server",
    "45.33.22.11": "Known_Botnet_Scanner",
    "192.168.1.50": "Insider_Threat_Watchlist"
}

# --- Models ---
class LogEntry(BaseModel):
    timestamp: Optional[str] = None
    source_ip: str
    destination_ip: str
    protocol: str
    severity: str
    message: str
    event_id: int

# --- WebSocket Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# --- Global Stats Counter (InMemory for Speed) ---
LOGS_LAST_SECOND = 0

# --- CORE ENGINEERING: Analysis Engine ---
def analyze_log(log: LogEntry):
    threat_score = 0
    threat_type = "None"
    mitre_id = "N/A"
    
    # 1. Threat Intel Check
    if log.source_ip in THREAT_INTEL_FEED:
        threat_score += 100
        threat_type = f"Intel Hit: {THREAT_INTEL_FEED[log.source_ip]}"
        log.severity = "CRITICAL"
        mitre_id = "T1071" # C2 Traffic

    # 2. SQL Injection (Pattern Matching)
    elif "SELECT *" in log.message or "UNION SELECT" in log.message:
        threat_score += 90
        threat_type = "SQL Injection Attempt"
        log.severity = "CRITICAL"
        mitre_id = "T1190" # Exploit Public-Facing Application
    
    # 3. Brute Force (Contextual)
    elif "User Login Failed" in log.message and log.severity == "HIGH":
        threat_score += 60
        threat_type = "Brute Force"
        mitre_id = "T1110" # Brute Force

    # 4. Port Scan (Heuristic)
    elif log.protocol == "TCP" and log.destination_ip == "192.168.1.100" and log.event_id == 999:
        threat_score += 40
        threat_type = "Port Scan"
        log.severity = "WARN"
        mitre_id = "T1046" # Network Service Discovery

    if threat_score > 50:
        return {
            "timestamp": datetime.now().isoformat(),
            "source_ip": log.source_ip,
            "type": threat_type,
            "severity": log.severity,
            "score": threat_score,
            "mitre_id": mitre_id
        }
    return None

# --- API ROUTES ---

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
templates = Jinja2Templates(directory=FRONTEND_DIR)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/dashboard")
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.post("/api/ingest")
async def ingest_log(log: LogEntry):
    if not log.timestamp:
        log.timestamp = datetime.now().isoformat()
    
    global LOGS_LAST_SECOND
    LOGS_LAST_SECOND += 1

    # 1. Persistence (Write to DB)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, source_ip, destination_ip, protocol, severity, message, event_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (log.timestamp, log.source_ip, log.destination_ip, log.protocol, log.severity, log.message, log.event_id))
    
    # 2. Analysis
    threat = analyze_log(log)
    if threat:
        c.execute("INSERT INTO threats (timestamp, source_ip, type, severity, score, mitre_id) VALUES (?, ?, ?, ?, ?, ?)",
                  (threat['timestamp'], threat['source_ip'], threat['type'], threat['severity'], threat['score'], threat['mitre_id']))
    
    conn.commit()
    conn.close()
    
    # 3. Real-time Broadcast
    msg = {
        "event": "new_log",
        "data": log.dict(),
        "threat": threat
    }
    await manager.broadcast(json.dumps(msg))
    
    return {"status": "ingested"}

@app.get("/api/incidents")
async def get_incidents():
    """Fetch recent threats for the Incidents Tab"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.get("/api/network")
async def get_network_topology():
    """Fetch active connections for the Network Map"""
    # Get distinct connections from the last 100 logs
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT source_ip, destination_ip, MAX(timestamp) as last_seen FROM logs GROUP BY source_ip, destination_ip ORDER BY id DESC LIMIT 20")
    links = c.fetchall()
    conn.close()
    
    nodes = set()
    edges = []
    
    for src, dst, ts in links:
        nodes.add(src)
        nodes.add(dst)
        edges.append({"source": src, "target": dst, "last_seen": ts})
        
    return {
        "nodes": list(nodes),
        "edges": edges
    }

@app.get("/api/sources")
async def get_log_sources():
    """Mock status of log collectors"""
    return [
        {"name": "Syslog UDP:514", "status": "active", "ip": "0.0.0.0", "type": "Network"},
        {"name": "API Ingestion (HTTP)", "status": "active", "ip": "0.0.0.0", "type": "Web"},
        {"name": "Windows Agent (WinRM)", "status": "active", "ip": "192.168.1.50", "type": "Endpoint"},
        {"name": "Firewall Stream", "status": "active", "ip": "192.168.1.1", "type": "Network"}
    ]

@app.get("/api/export")
async def export_logs():
    """Forensic Export: Dump DB to CSV"""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM logs", conn)
    conn.close()
    
    export_path = "logs_dump.csv"
    df.to_csv(export_path, index=False)
    return FileResponse(export_path, filename="soc_logs_dump.csv", media_type="text/csv")

# --- BACKGROUND WORKER ---
async def broadcast_stats():
    global LOGS_LAST_SECOND
    while True:
        await asyncio.sleep(1)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT COUNT(*) FROM logs")
            row = c.fetchone()
            total_logs = row[0] if row else 0
            
            c.execute("SELECT COUNT(*) FROM threats")
            row2 = c.fetchone()
            total_threats = row2[0] if row2 else 0
        except:
            total_logs = 0
            total_threats = 0
        finally:
            conn.close()

        stats = {
            "event": "system_stats",
            "fps": LOGS_LAST_SECOND,
            "total_logs": total_logs,
            "total_threats": total_threats
        }
        await manager.broadcast(json.dumps(stats))
        LOGS_LAST_SECOND = 0

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(broadcast_stats())

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
