# SOC-Based Log Analysis and Threat Correlation System
## Architectural Design & Implementation Plan (v2.0)

### 1. Project Overview
This project is a high-performance, centralized Security Operations Center (SOC) dashboard designed to ingest, analyze, store, and correlate logs from various sources to detect security threats in real-time. It mimics enterprise SIEM tools (e.g., Splunk, Wazuh) but leverages a custom Python-driven architecture for maximum control and educational value in Cybersecurity Engineering.

---

### 2. System Architecture

#### A. Data Layer (Persistence & Ingestion)
- **Database**: SQLite (`soc_logs.db`).
  - **Schema**: Relational tables for `logs` (raw events) and `threats` (correlated incidents).
  - **Purpose**: Ensures data persistence across reboots and enables forensic historical queries.
- **Ingestion Mechanisms**: 
  - **REST API**: `/api/ingest` endpoint for receiving JSON formatted logs from agents.
  - **Simulator**: `tools/log_simulator.py` generates realistic traffic patterns (HTTP, SSH, RDP) mixed with attack signatures.

#### B. Processing Layer (The "Brain")
- **FastAPI Core**: Asynchronous Python backend handling high-throughput log intake.
- **Correlation Engine**: 
  - **Rule-Based Detection**: Maps events to known attack patterns (e.g., Event ID 4625 for Brute Force).
  - **Signature Matching**: Regex analysis for SQL Injection (`UNION SELECT`) and Cross-Site Scripting (XSS).
- **Threat Intelligence**: 
  - **MITRE ATT&CK Mapping**: Automatically tags detected threats with Framework IDs (e.g., `T1110` for Brute Force, `T1190` for Exploits).
  - **Intel Feeds**: Checks Source IPs against a known malicious indicator list (Simulated C2 Servers).

#### C. Presentation Layer (Frontend)
- **Technology**: Vanilla HTML5/CSS3 + JavaScript (ES6). No heavy frameworks to ensure lightweight, instant loading.
- **Communication**: WebSockets (`ws://`) for sub-millisecond real-time UI updates.
- **Modules**:
  1.  **Live Dashboard**: Real-time "Matrix-style" log scrolling and EPS (Events Per Second) monitoring.
  2.  **Incidents Tab**: Tabular view of high-severity threats with MITRE tagging and score.
  3.  **Network Map**: HTML5 Canvas visualization rendering a dynamic topology of Active vs. Malicious nodes.
  4.  **Log Sources**: Health monitoring of connected agents and data streams.

#### D. API Layer (Interfaces)
- **Endpoints**:
  - `GET /api/incidents`: Fetch historical alerts.
  - `GET /api/network`: Aggregates active connections for the graph topology.
  - `GET /api/export`: Generates forensic CSV dumps of the database.
  - `WS /ws/logs`: Stream for live event broadcasting.

---

### 3. Key Technical Specifications
- **Backend Language**: Python 3.10+ (FastAPI, Pandas, SQLite).
- **Frontend Language**: Native JavaScript (Canvas API for Graphing).
- **Concurrency**: `asyncio` for non-blocking log processing and WebSocket broadcasting.
- **Security**: Input sanitization on ingestion; CORS policies enabled.

---

### 4. Implementation Modules

1.  **`Analyzer`**: The logic core containing the Threat Detection Rules and Scoring Algorithm.
2.  **`Persistence`**: SQLite Wrapper for efficient Insert/Select operations on log data.
3.  **`Visualizer`**: Frontend Canvas logic to draw the force-directed network graph.
4.  **`Simulator`**: Advanced tool to generate "Attack Scenarios" (SQLi, C2, Brute Force) for demonstration.

---

### 5. Execution Workflow
1.  **Start Core**: `run_soc.bat` launches the FastAPI Server and initializes the Database.
2.  **Start Agent**: `run_simulation.bat` begins sending traffic to the Core.
3.  **Monitor**: Operator uses the Web Interface to view the real-time attack surface and respond to alerts.
