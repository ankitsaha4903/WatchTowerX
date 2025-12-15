# WatchTowerX - Advanced Threat Correlation System

**WatchTowerX** is a next-generation Security Operations Center (SOC) dashboard designed for real-time threat detection, log analysis, and visualization.

![WatchTowerX Dashboard](https://github.com/project8777793821-coder/WatchTowerX/raw/main/screenshot_demo.png) *(Placeholder)*

## 🚀 Features

*   **Real-time Log Ingestion**: High-throughput asyncio backend (FastAPI).
*   **Live Attack Map**: HTML5 Canvas visualization of network topology.
*   **Threat Intelligence**: Integrated MITRE ATT&CK mapping (e.g., T1110 Brute Force).
*   **Cyber-Security Theme**: Premium "Sci-Fi" UI with glassmorphism and animations.
*   **Forensics**: SQLite persistence and CSV export capabilities.

## 🛠️ Tech Stack

*   **Backend**: Python, FastAPI, SQLite, Pandas.
*   **Frontend**: Vanilla JS, HTML5, CSS3 (No heavy frameworks).
*   **Protocol**: WebSockets for live data streaming.

## 📦 Installation & Usage

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/project8777793821-coder/WatchTowerX.git
    cd WatchTowerX
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the SOC Backend**
    ```bash
    run_soc.bat
    # OR
    python -m uvicorn backend.main:app --reload
    ```

4.  **Run Traffic Simulator (Optional)**
    ```bash
    run_simulation.bat
    ```

5.  **Access Dashboard**
    Open [http://localhost:8000/dashboard](http://localhost:8000/dashboard)

## 👤 Author
**Ankit Saha**
WatchTowerX © 2025
