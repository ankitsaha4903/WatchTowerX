@echo off
REM Windows quick start script
IF NOT EXIST .venv (
    python -m venv .venv
)
call .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app\main.py
