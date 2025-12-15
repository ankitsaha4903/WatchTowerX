# dashboard.py

import io
import csv
import time
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from db import (
    init_db,
    get_connection,
    set_policy,
    get_policies,
    set_device_status_by_id,
    get_device_by_id,
    check_user_password,
    get_user_by_id,
    get_sensitive_regex,
    add_sensitive_regex,
    delete_sensitive_regex,
    get_sensitive_keywords,
    add_sensitive_keyword,
    delete_sensitive_keyword,
    create_user,
    get_user_by_email,
    get_user_by_phone,
    verify_phone
)
from config import DB_PATH
from pyngrok import ngrok
import sys

app = Flask(__name__)
app.secret_key = "usb_guard_secret_key"  # for flash messages

# Initialize DB once when app starts
init_db()

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_id(int(user_id))
    if user_data:
        return User(id=user_data['id'], username=user_data['username'])
    return None

# --- Routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user_data = check_user_password(username, password)
        
        if user_data:
            user = User(id=user_data['id'], username=user_data['username'])
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.", "danger")
            
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


# --- Registration Routes ---

@app.route("/register", methods=["GET", "POST"])
def register():
    """Main registration page"""
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    if request.method == "POST":
        auth_method = request.form.get("auth_method", "password")
        
        if auth_method == "password":
            return handle_password_registration()
        elif auth_method == "phone":
            return handle_phone_registration()
    
    return render_template("login.html", show_register=True)


def handle_password_registration():
    """Handle traditional username/password registration"""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    device_type = request.form.get("device_type", "")
    model_name = request.form.get("model_name", "").strip()
    
    # Validation
    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for("register"))
    
    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("register"))
    
    if len(password) < 6:
        flash("Password must be at least 6 characters.", "danger")
        return redirect(url_for("register"))
    
    # Create user
    success = create_user(
        username=username,
        password=password,
        auth_method='password',
        device_type=device_type,
        model_name=model_name
    )
    
    if success:
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))
    else:
        flash("Username already exists. Please choose another.", "danger")
        return redirect(url_for("register"))


def handle_phone_registration():
    """Handle phone number registration with OTP"""
    phone_number = request.form.get("phone_number", "").strip()
    otp_code = request.form.get("otp_code", "").strip()
    device_type = request.form.get("device_type", "")
    model_name = request.form.get("model_name", "").strip()
    
    if not phone_number:
        flash("Phone number is required.", "danger")
        return redirect(url_for("register"))
    
    # Check if requesting OTP or verifying
    if not otp_code:
        # Generate and send OTP
        import random
        otp = str(random.randint(100000, 999999))
        app.config['pending_otp'] = {phone_number: otp}  # Store temporarily
        
        # TODO: Send OTP via Twilio
        # For now, just show it in flash message for testing
        flash(f"OTP sent to {phone_number}. (Test OTP: {otp})", "success")
        return render_template("login.html", show_register=True, show_otp=True, phone_number=phone_number)
    else:
        # Verify OTP
        stored_otp = app.config.get('pending_otp', {}).get(phone_number)
        if stored_otp and stored_otp == otp_code:
            # Create user
            username = f"user_{phone_number[-4:]}"  # Generate username from phone
            success = create_user(
                username=username,
                phone_number=phone_number,
                auth_method='phone',
                device_type=device_type,
                model_name=model_name
            )
            
            if success:
                # Get user and verify phone
                user_data = get_user_by_phone(phone_number)
                if user_data:
                    verify_phone(user_data['id'])
                
                flash("Account created successfully! Please log in with your username: " + username, "success")
                return redirect(url_for("login"))
            else:
                flash("Error creating account. Phone number may already be registered.", "danger")
        else:
            flash("Invalid OTP code.", "danger")
        
        return redirect(url_for("register"))


@app.route("/register/google")
def register_google():
    """Initiate Google OAuth flow"""
    # TODO: Implement Google OAuth
    # For now, redirect back with message
    flash("Google OAuth registration coming soon! Please use password registration.", "warning")
    return redirect(url_for("register"))


@app.route("/")
@login_required
def index():
    conn = get_connection()
    cur = conn.cursor()
    # Recent logs
    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 20;")
    logs = cur.fetchall()
    # Stats
    cur.execute("SELECT COUNT(*) AS c FROM devices;")
    devices_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM logs;")
    logs_count = cur.fetchone()["c"]
    conn.close()
    return render_template(
        "index.html",
        logs=logs,
        devices_count=devices_count,
        logs_count=logs_count,
        db_path=DB_PATH,
    )


@app.route("/devices")
@login_required
def devices():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices ORDER BY last_seen DESC;")
    devices_rows = cur.fetchall()
    conn.close()
    return render_template("devices.html", devices=devices_rows)


@app.route("/devices/allow/<int:device_id>")
@login_required
def allow_device(device_id):
    row = get_device_by_id(device_id)
    if row:
        set_device_status_by_id(device_id, "allowed", "whitelisted")
        flash(f"Device at {row['mount_point']} marked as TRUSTED / ALLOWED.", "success")
    else:
        flash("Device not found.", "danger")
    return redirect(url_for("devices"))


@app.route("/devices/block/<int:device_id>")
@login_required
def block_device(device_id):
    row = get_device_by_id(device_id)
    if row:
        set_device_status_by_id(device_id, "blocked", "manually_blocked")
        flash(f"Device at {row['mount_point']} marked as BLOCKED.", "danger")
    else:
        flash("Device not found.", "danger")
    return redirect(url_for("devices"))


@app.route("/logs")
@login_required
def logs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200;")
    logs_rows = cur.fetchall()
    conn.close()
    return render_template("logs.html", logs=logs_rows)


@app.route("/api/export_logs")
@login_required
def export_logs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT timestamp, level, event_type, username, device_id, mount_point, message FROM logs ORDER BY id DESC;")
    logs_rows = cur.fetchall()
    conn.close()

    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Level", "Event Type", "User", "Device ID", "Mount Point", "Message"])
    
    for row in logs_rows:
        writer.writerow([row['timestamp'], row['level'], row['event_type'], row['username'], row['device_id'], row['mount_point'], row['message']])
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=usb_guard_logs.csv"}
    )


@app.route("/sensitive-paths", methods=["GET", "POST"])
@login_required
def sensitive_paths():
    conn = get_connection()
    cur = conn.cursor()

    if request.method == "POST":
        path = request.form.get("path", "").strip()
        if path:
            try:
                cur.execute(
                    "INSERT OR IGNORE INTO sensitive_paths (path) VALUES (?);",
                    (path,),
                )
                conn.commit()
                flash("Sensitive path added.", "success")
            except Exception as e:
                flash(f"Error adding path: {e}", "danger")
        conn.close()
        return redirect(url_for("sensitive_paths"))

    cur.execute("SELECT * FROM sensitive_paths;")
    rows = cur.fetchall()
    conn.close()
    return render_template("sensitive_paths.html", paths=rows)


@app.route("/sensitive-paths/delete/<int:path_id>")
@login_required
def delete_sensitive_path(path_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM sensitive_paths WHERE id=?;", (path_id,))
    conn.commit()
    conn.close()
    flash("Path removed.", "success")
    return redirect(url_for("sensitive_paths"))


@app.route("/sensitive-keywords", methods=["GET", "POST"])
@login_required
def sensitive_keywords():
    # Handle simple keywords
    if request.method == "POST" and "keyword" in request.form:
        keyword = request.form.get("keyword", "").strip()
        if keyword:
            try:
                add_sensitive_keyword(keyword)
                flash("Sensitive keyword added.", "success")
            except Exception as e:
                flash(f"Error adding keyword: {e}", "danger")
        return redirect(url_for("sensitive_keywords"))
    
    # Handle Regex
    if request.method == "POST" and "regex_pattern" in request.form:
        pattern = request.form.get("regex_pattern", "").strip()
        description = request.form.get("description", "").strip()
        if pattern:
            try:
                add_sensitive_regex(pattern, description)
                flash("Regex pattern added.", "success")
            except Exception as e:
                flash(f"Error adding regex: {e}", "danger")
        return redirect(url_for("sensitive_keywords"))

    keywords = get_sensitive_keywords()
    regex_patterns = get_sensitive_regex()
    
    return render_template("keywords.html", keywords=keywords, regex_patterns=regex_patterns)


@app.route("/sensitive-keywords/delete/<int:keyword_id>")
@login_required
def delete_sensitive_keyword_route(keyword_id):
    delete_sensitive_keyword(keyword_id)
    flash("Keyword removed.", "success")
    return redirect(url_for("sensitive_keywords"))


@app.route("/sensitive-regex/delete/<int:regex_id>")
@login_required
def delete_sensitive_regex_route(regex_id):
    delete_sensitive_regex(regex_id)
    flash("Regex pattern removed.", "success")
    return redirect(url_for("sensitive_keywords"))


@app.route("/policies", methods=["GET", "POST"])
@login_required
def policies():
    if request.method == "POST":
        default_usb_action = request.form.get("default_usb_action", "block_unknown")
        log_file_events = request.form.get("log_file_events", "false")
        alert_on_block = request.form.get("alert_on_block", "false")
        alert_email = request.form.get("alert_email", "").strip()

        set_policy("default_usb_action", default_usb_action)
        set_policy("log_file_events", log_file_events)
        set_policy("alert_on_block", alert_on_block)
        set_policy("alert_email", alert_email)

        flash("Policies updated successfully.", "success")
        return redirect(url_for("policies"))

    policies_data = get_policies()
    return render_template("policies.html", policies=policies_data)


# ------------------------------
#  Real-time API for dashboard
# ------------------------------
@app.route("/api/overview")
@login_required
def api_overview():
    """
    Returns JSON with:
    - devices_count: total number of devices
    - logs_count: total number of log entries
    - logs: last 20 log entries
    Used by the dashboard.js on index.html to update in near real-time.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM devices;")
    devices_count = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM logs;")
    logs_count = cur.fetchone()["c"]

    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 20;")
    logs_rows = cur.fetchall()
    logs = [dict(row) for row in logs_rows]

    conn.close()

    return jsonify(
        {
            "devices_count": devices_count,
            "logs_count": logs_count,
            "logs": logs,
        }
    )

# --- Real-time Monitor ---

@app.route("/monitor")
@login_required
def monitor():
    return render_template("monitor.html")

@app.route("/api/stream")
@login_required
def stream():
    def event_stream():
        conn = get_connection()
        cur = conn.cursor()
        last_id = 0
        
        # Get the last ID to start from
        cur.execute("SELECT MAX(id) as max_id FROM logs")
        row = cur.fetchone()
        if row and row['max_id']:
            last_id = row['max_id']
        conn.close()

        while True:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM logs WHERE id > ? ORDER BY id ASC", (last_id,))
            rows = cur.fetchall()
            conn.close()
            
            if rows:
                for row in rows:
                    last_id = row['id']
                    # Format data for SSE
                    data = {
                        "timestamp": row['timestamp'],
                        "level": row['level'],
                        "event_type": row['event_type'],
                        "message": row['message']
                    }
                    yield f"data: {jsonify(data).get_data(as_text=True)}\n\n"
            
            time.sleep(0.5) # Poll every 0.5s for responsiveness

    return Response(event_stream(), mimetype="text/event-stream")

# --- Trust Modal API ---

@app.route("/api/pending_devices")
@login_required
def pending_devices():
    """
    Returns list of devices with status 'pending_approval'
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE status = 'pending_approval';")
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route("/api/approve_device/<int:device_id>", methods=["POST"])
@login_required
def approve_device(device_id):
    """
    Approve a pending device
    """
    set_device_status_by_id(device_id, "allowed", "user_approved")
    return jsonify({"status": "success"})

@app.route("/api/block_device/<int:device_id>", methods=["POST"])
@login_required
def block_device_api(device_id):
    """
    Block a pending device
    """
    set_device_status_by_id(device_id, "blocked", "user_blocked")
    return jsonify({"status": "success"})


if __name__ == "__main__":
    # ---------------------------------------------------------
    # GLOBAL SECURE ACCESS (Ngrok)
    # ---------------------------------------------------------
    # Open a Ngrok tunnel to the local port 5000
    # This provides a public HTTPS URL with a valid certificate
    try:
        public_url = ngrok.connect(5000).public_url
        print("\n" + "="*60)
        print(f" GLOBAL ACCESS URL: {public_url}")
        print("="*60 + "\n")
    except Exception as e:
        print(f"Ngrok error: {e}")

    # Run locally on HTTP (Ngrok handles the HTTPS encryption globally)
    app.run(
        host='0.0.0.0',  # Listen on all interfaces
        port=5000,
        debug=True,
        threaded=True
        # ssl_context removed - Ngrok provides the Green Lock
    )
