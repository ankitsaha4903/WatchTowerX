# VirusTotal Analyzer — Zero-Experience Quickstart

This guide is written for absolute beginners. Follow each step exactly; you don't need prior cyber security knowledge.

---

## 1) What this app does (in plain English)
- You paste a **website link** (URL) or a **file fingerprint** (called a *hash*) into the app.
- The app asks **VirusTotal** (a big online database of threats) if that website/file looks **safe or dangerous**.
- The app shows the result on screen and **saves a copy** in a small local database so you can view it later.
- You can **export** the results as CSV or JSON files to show your teacher/mentor.

---

## 2) Install the one thing you need: Python
- Download Python 3.11+ from https://www.python.org/downloads/ and install it.
- During install on Windows, tick “Add python.exe to PATH” if it appears.

---

## 3) Get a VirusTotal API key (free)
1. Go to https://www.virustotal.com/ and create a free account.
2. After login, click your profile (top-right) → “API key”.
3. Copy the key (looks like a long string of letters/numbers).

> This key tells VirusTotal that **you** are asking for information.
> Free keys have limits. If you ask too often, VirusTotal says “Too many requests — try later”.

---

## 4) Put your key into `.env`
1. In your project folder, copy the file **`.env.example`** and rename the copy to **`.env`** (no extension).
2. Open `.env` in a text editor and replace `PUT-YOUR-REAL-KEY-HERE` with your real API key.
3. Save the file.

---

## 5) Open a terminal in your project folder
- **Windows:** Open “Windows Terminal” or “PowerShell”, then `cd` to your project folder.
- **macOS/Linux:** Open Terminal app, then `cd` to your project folder.

Example:
```
cd path/to/your/repo
```

---

## 6) Create a sandbox (virtual environment) and install libraries
### macOS / Linux
```
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Windows (PowerShell)
```
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

> If activation is blocked on Windows, run PowerShell as Administrator once and execute:
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

---

## 7) Create folders for the database and exports (once)
```
mkdir data exports
```

---

## 8) Start the app
```
streamlit run app/main.py
```
- Your browser will open at `http://localhost:8501`.
- If something already uses that port, use:
```
streamlit run app/main.py --server.port 8502
```

---

## 9) How to use the app (like a checklist)
1. Paste a **URL** (like `https://example.com`) **or** a **hash** (a fingerprint such as SHA-256).
2. Click **Analyze**.
3. Read the result:
   - **Malicious / Suspicious / Harmless / Undetected** (these are votes from many security vendors).
4. Click **Export** to save a CSV/JSON report into the `exports/` folder.
5. Go to **History** to see older scans without spending your VirusTotal quota again.

---

## 10) Troubleshooting (plain English)
- **“API key invalid”** → Your `.env` is missing or the key is wrong. Open `.env`, fix the key, then restart the app.
- **“Too many requests (429)”** → You asked VirusTotal too often. Wait a few minutes. Use **History** to re-open past results.
- **“Module not found”** → Re-activate the virtual environment and run `pip install -r requirements.txt` again.
- **“Port already in use”** → Add `--server.port 8502` to the run command.
- **Blank page** → Stop the app (Ctrl+C in terminal) and run it again.

---

## 11) What are those scary words?
- **URL:** a website link.
- **Hash (MD5/SHA-1/SHA-256):** a short ID that uniquely represents a file. It’s like a fingerprint for files.
- **VirusTotal:** a website where many antivirus engines vote on whether a file/URL looks bad.

---

## 12) Safety notes
- Do not upload illegal content. For files, only analyze samples you are allowed to use.
- Your free VirusTotal key is personal—don’t share it publicly or commit it to Git.

You’re done! 🎉  If you can open the app, scan a URL, and export a report, your project is working end-to-end.
