# VirusTotal Threat Analyzer

A Streamlit web app to analyze URLs and file hashes using the VirusTotal v3 API.

## Features
- Scan a URL (polls until analysis completes on VirusTotal).
- Lookup a file hash (SHA256/SHA1/MD5) and show last-analysis stats.
- Save results locally in SQLite and export as CSV.
- Simple, clean UI suitable for a final-year project demo.

## Setup (Quick Start)
1. Install Python 3.10+
2. Create a virtual environment and activate it
3. `pip install -r requirements.txt`
4. Create a `.env` file and set `VT_API_KEY=YOUR_KEY`
5. Run: `streamlit run app/main.py`

## Notes
- Free VirusTotal API keys are rate-limited.
- Educational demo; follow VirusTotal Terms of Service.
