# Streamlit Dashboard Guide (Virtual Environment)

## Overview
The USB Guard dashboard runs in a **Virtual Environment** to ensure stability and avoid permission errors.

## 🚀 How to Run (Recommended)

**Double-click the `run_app.bat` file** in the project folder.

This will automatically:
1.  Activate the virtual environment.
2.  Launch the Streamlit dashboard.
3.  Open it in your browser.

## Manual Method (Command Line)
If you prefer using the terminal:

1.  Open terminal in project folder.
2.  Activate environment:
    ```powershell
    .\venv\Scripts\activate
    ```
3.  Run app:
    ```bash
    streamlit run streamlit_app.py
    ```

## Features
- **Cyberpunk Theme**: Custom CSS styling for neon aesthetics.
- **Authentication**: Login and Registration (Password, Phone/OTP).
- **Live Monitor**: Auto-refreshing log viewer.
- **Interactive Charts**: Plotly-based activity graphs.
- **Device Management**: Trust or Block devices with a click.

## Troubleshooting
- **"streamlit is not recognized"**: Make sure you activated the venv first!
- **Database Locked**: Ensure no other instances are running.
