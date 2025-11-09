# Run the VirusTotal Analyzer (PowerShell)
# Usage: right-click -> Run with PowerShell (or execute inside a PowerShell window)
$ErrorActionPreference = "Stop"

if (!(Test-Path ".\.venv")) {
  py -3 -m venv .venv
}

. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

if (!(Test-Path ".\data")) { New-Item -ItemType Directory -Path ".\data" | Out-Null }
if (!(Test-Path ".\exports")) { New-Item -ItemType Directory -Path ".\exports" | Out-Null }

streamlit run app/main.py
