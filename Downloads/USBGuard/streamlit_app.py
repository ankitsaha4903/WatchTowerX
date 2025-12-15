import streamlit as st
import pandas as pd
import plotly.express as px
import time
from datetime import datetime
import db

# --- Page Configuration ---
st.set_page_config(
    page_title="USB Guard Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Premium Cyberpunk Theme CSS ---
def local_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600&family=Rajdhani:wght@300;400;500;600&family=Inter:wght@300;400;600&display=swap');

        :root {
            /* Soothing Cyber Palette */
            --bg-deep: #0f172a;       /* Deep Slate Blue */
            --bg-lighter: #1e293b;    /* Lighter Slate */
            --accent-cyan: #38bdf8;   /* Soft Sky Blue */
            --accent-purple: #818cf8; /* Soft Indigo */
            --accent-teal: #2dd4bf;   /* Soft Teal */
            --text-main: #f1f5f9;     /* Off-white */
            --text-dim: #94a3b8;      /* Muted Blue-Grey */
            --glass-panel: rgba(30, 41, 59, 0.7);
            --glass-border: rgba(56, 189, 248, 0.2);
        }

        /* --- Main Background --- */
        .stApp {
            background-color: var(--bg-deep);
            background-image: 
                radial-gradient(circle at 15% 50%, rgba(56, 189, 248, 0.08) 0%, transparent 25%),
                radial-gradient(circle at 85% 30%, rgba(129, 140, 248, 0.08) 0%, transparent 25%);
            font-family: 'Inter', sans-serif;
            color: var(--text-main);
        }

        /* --- Sidebar --- */
        section[data-testid="stSidebar"] {
            background-color: rgba(15, 23, 42, 0.95);
            border-right: 1px solid rgba(255, 255, 255, 0.05);
            box-shadow: 10px 0 30px rgba(0, 0, 0, 0.2);
        }

        /* --- Typography --- */
        h1, h2, h3 {
            font-family: 'Orbitron', sans-serif !important;
            letter-spacing: 1px;
            color: var(--text-main);
        }

        h1 {
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 600 !important;
            text-shadow: 0 0 30px rgba(56, 189, 248, 0.3);
            margin-bottom: 1.5rem !important;
        }

        h2 {
            font-size: 1.5rem !important;
            color: var(--accent-cyan) !important;
            margin-bottom: 1rem !important;
        }
        
        p, label, .stMarkdown, li {
            font-family: 'Rajdhani', sans-serif;
            font-size: 1.15rem;
            color: var(--text-dim);
            line-height: 1.7;
        }

        /* --- Inputs --- */
        .stTextInput > div > div > input, 
        .stSelectbox > div > div > div,
        .stTextArea > div > div > textarea {
            background-color: rgba(30, 41, 59, 0.6) !important;
            border: 1px solid rgba(148, 163, 184, 0.2) !important;
            color: var(--text-main) !important;
            border-radius: 8px !important;
            font-family: 'Inter', sans-serif !important;
            transition: all 0.3s ease;
        }

        .stTextInput > div > div > input:focus,
        .stSelectbox > div > div > div:focus,
        .stTextArea > div > div > textarea:focus {
            border-color: var(--accent-cyan) !important;
            background-color: rgba(30, 41, 59, 0.9) !important;
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2) !important;
        }

        /* --- Buttons --- */
        div.stButton > button {
            background: linear-gradient(135deg, rgba(56, 189, 248, 0.1), rgba(129, 140, 248, 0.1)) !important;
            border: 1px solid var(--glass-border) !important;
            color: var(--accent-cyan) !important;
            font-family: 'Orbitron', sans-serif !important;
            font-weight: 600;
            border-radius: 8px !important;
            padding: 0.6rem 1.5rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        div.stButton > button:hover {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple)) !important;
            color: #fff !important;
            border-color: transparent !important;
            box-shadow: 0 10px 20px -5px rgba(56, 189, 248, 0.4);
            transform: translateY(-2px);
        }

        /* --- Cards / Metrics --- */
        div[data-testid="stMetric"] {
            background: linear-gradient(180deg, rgba(30, 41, 59, 0.6), rgba(15, 23, 42, 0.6));
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 20px;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        div[data-testid="stMetricLabel"] {
            color: var(--text-dim) !important;
            font-family: 'Inter', sans-serif;
            font-size: 0.9rem !important;
            letter-spacing: 0.5px;
        }

        div[data-testid="stMetricValue"] {
            color: var(--text-main) !important;
            font-family: 'Orbitron', sans-serif;
            font-weight: 600;
        }

        /* --- Expanders --- */
        div[data-testid="stExpander"] {
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
        }

        .streamlit-expanderHeader {
            background-color: rgba(30, 41, 59, 0.4) !important;
            color: var(--accent-cyan) !important;
            font-family: 'Rajdhani', sans-serif !important;
            font-weight: 600;
            font-size: 1.1rem !important;
            border-radius: 12px !important;
            transition: background 0.2s;
        }
        
        .streamlit-expanderHeader:hover {
            background-color: rgba(56, 189, 248, 0.1) !important;
        }

        div[data-testid="stExpanderDetails"] {
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            padding-top: 1rem;
        }

        /* --- Tabs --- */
        .stTabs [data-baseweb="tab-list"] {
            gap: 24px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .stTabs [data-baseweb="tab"] {
            background: transparent;
            border: none;
            color: var(--text-dim);
            font-family: 'Rajdhani', sans-serif;
            font-weight: 500;
            padding-bottom: 12px;
        }

        .stTabs [aria-selected="true"] {
            color: var(--accent-cyan) !important;
            border-bottom: 2px solid var(--accent-cyan);
        }

        /* --- DataFrames --- */
        div[data-testid="stDataFrame"] {
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            background: rgba(15, 23, 42, 0.5);
        }

        /* --- Alerts --- */
        div[data-baseweb="notification"] {
            border-radius: 12px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }
        
        /* --- Scrollbar --- */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: var(--bg-deep); 
        }
        ::-webkit-scrollbar-thumb {
            background: #334155; 
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #475569; 
        }

    </style>
    """, unsafe_allow_html=True)

local_css()

# --- Session State Management ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user' not in st.session_state:
    st.session_state.user = None
if 'page' not in st.session_state:
    st.session_state.page = "Login"

# --- Authentication Functions ---
def login_page():
    st.title("🛡️ USB Guard Login")
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.image("https://img.icons8.com/nolan/96/usb.png", width=100)
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            user = db.check_user_password(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.user = user
                st.session_state.page = "Dashboard"
                st.rerun()
            else:
                st.error("Invalid username or password")
    
    st.markdown("---")
    if st.button("Create New Account"):
        st.session_state.page = "Register"
        st.rerun()

def register_page():
    st.title("📝 Create Account")
    
    tab1, tab2, tab3 = st.tabs(["Password", "Google", "Email"])
    
    with tab1:
        with st.form("register_form"):
            new_user = st.text_input("Username")
            new_pass = st.text_input("Password", type="password")
            confirm_pass = st.text_input("Confirm Password", type="password")
            device_type = st.selectbox("Device Type", ["Laptop/Monitor", "Mobile/Phone"])
            model_name = st.text_input("Model Name (e.g. Dell XPS 15)")
            
            if st.form_submit_button("Register"):
                if new_pass != confirm_pass:
                    st.error("Passwords do not match")
                elif len(new_pass) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    if db.create_user(username=new_user, password=new_pass, device_type=device_type, model_name=model_name):
                        st.success("Account created! Please login.")
                        time.sleep(1)
                        st.session_state.page = "Login"
                        st.rerun()
                    else:
                        st.error("Username already exists")

    with tab2:
        st.info("Google OAuth coming soon!")
        
    with tab3:
        st.info("Email Registration (OTP Verification)")
        
        # Check for credentials
        import os
        from dotenv import load_dotenv
        load_dotenv()
        if not os.getenv("GMAIL_ADDRESS"):
            st.warning("⚠️ Gmail credentials not found in .env file. Email OTP will not work.")
            st.markdown("Please configure `GMAIL_ADDRESS` and `GMAIL_APP_PASSWORD` in your `.env` file.")
        
        email_input = st.text_input("Email Address", placeholder="user@example.com")
        
        if 'generated_otp' not in st.session_state:
            st.session_state.generated_otp = None
        
        if 'email_verified' not in st.session_state:
            st.session_state.email_verified = False
            
        if st.button("Send OTP"):
            if not email_input or "@" not in email_input:
                st.error("Please enter a valid email address.")
            else:
                import email_utils
                with st.spinner(f"Sending OTP to {email_input}..."):
                    otp, status = email_utils.send_otp_email(email_input)
                    if otp:
                        st.session_state.generated_otp = otp
                        if status == "TEST_MODE":
                            st.warning(f"⚠️ Test Mode (Placeholder Credentials). Your OTP is: **{otp}**")
                        else:
                            st.success("OTP sent successfully! Check your email inbox.")
                    else:
                        st.error(f"Failed to send OTP: {status}")
        
        otp_input = st.text_input("Enter OTP")
        
        if not st.session_state.email_verified:
            if st.button("Verify OTP"):
                if st.session_state.generated_otp and otp_input == st.session_state.generated_otp:
                    st.session_state.email_verified = True
                    st.success("✅ Email Verified! Please set your account details below.")
                    st.rerun()
                else:
                    st.error("Invalid OTP or OTP expired.")
        
        # Step 2: Set Username and Password (only shown after verification)
        if st.session_state.email_verified:
            st.markdown("### 🔐 Finalize Account Details")
            with st.form("finalize_email_signup"):
                custom_username = st.text_input("Choose Username")
                custom_password = st.text_input("Choose Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")
                
                # Device info (optional)
                dev_type = "Unknown"
                mod_name = "Unknown Device"
                
                if st.form_submit_button("Complete Registration"):
                    if not custom_username or not custom_password:
                        st.error("Please fill in all fields.")
                    elif custom_password != confirm_password:
                        st.error("Passwords do not match.")
                    elif len(custom_password) < 6:
                        st.error("Password must be at least 6 characters.")
                    else:
                        # Create user with custom credentials AND verified email
                        if db.create_user(username=custom_username, password=custom_password, email=email_input, auth_method='email', device_type=dev_type, model_name=mod_name):
                            st.success("🎉 Account created successfully!")
                            # Cleanup session state
                            st.session_state.generated_otp = None
                            st.session_state.email_verified = False
                            time.sleep(2)
                            st.session_state.page = "Login"
                            st.rerun()
                        else:
                            st.error("Email already registered or error creating user.")

    if st.button("Back to Login"):
        st.session_state.page = "Login"
        st.rerun()

# --- Dashboard Pages ---
def main_dashboard():
    st.title("📊 Dashboard Overview")
    
    # Metrics
    conn = db.get_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT COUNT(*) as c FROM devices")
    dev_count = cur.fetchone()['c']
    
    cur.execute("SELECT COUNT(*) as c FROM logs")
    log_count = cur.fetchone()['c']
    
    cur.execute("SELECT COUNT(*) as c FROM devices WHERE status='blocked'")
    blocked_count = cur.fetchone()['c']
    
    conn.close()
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Devices", dev_count)
    col2.metric("Total Logs", log_count)
    col3.metric("Blocked Devices", blocked_count, delta_color="inverse")
    
    # Charts
    st.subheader("Activity Log")
    conn = db.get_connection()
    df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC LIMIT 50", conn)
    conn.close()
    
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        fig = px.histogram(df, x="timestamp", color="event_type", 
                           title="Events over Time",
                           template="plotly_dark",
                           color_discrete_sequence=["#6366f1", "#8b5cf6", "#a855f7", "#ec4899"])
        fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e0e7ff",
            title_font_color="#818cf8"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Recent Activity")
    st.dataframe(df[['timestamp', 'event_type', 'device_id', 'message']], use_container_width=True)

def monitor_page():
    st.title("💻 Live Monitor")
    st.caption("Auto-refreshing every 2 seconds")
    
    # --- Pending Devices Section ---
    conn = db.get_connection()
    # Fetch pending devices
    pending_devices = pd.read_sql_query("SELECT * FROM devices WHERE status = 'pending_approval'", conn)
    conn.close()
    
    if not pending_devices.empty:
        st.warning("⚠️ New USB Device(s) Detected!")
        for index, row in pending_devices.iterrows():
            with st.expander(f"New Device: {row['mount_point']} ({row['device_id']})", expanded=True):
                st.write(f"**Vendor:** {row['vendor']}")
                st.write(f"**Product:** {row['product']}")
                st.write(f"**First Seen:** {row['first_seen']}")
                
                c1, c2 = st.columns(2)
                
                # Trust Button Logic
                if c1.button("✅ Trust Device", key=f"mon_trust_{row['id']}"):
                    # 1. Generate new Alias (Trust-N)
                    conn = db.get_connection()
                    cur = conn.cursor()
                    # Find all aliases starting with 'Trust-'
                    cur.execute("SELECT alias FROM devices WHERE alias LIKE 'Trust-%'")
                    aliases = [r['alias'] for r in cur.fetchall()]
                    conn.close()
                    
                    max_num = 0
                    for a in aliases:
                        try:
                            # Extract number from Trust-X
                            num = int(a.split('-')[1])
                            if num > max_num:
                                max_num = num
                        except (IndexError, ValueError):
                            pass
                    
                    new_alias = f"Trust-{max_num + 1}"
                    
                    # 2. Update Device
                    db.set_device_status_by_id(row['id'], "allowed", "user_approved")
                    db.update_device_alias(row['id'], new_alias)
                    
                    st.success(f"Device Trusted and named '{new_alias}'!")
                    time.sleep(1)
                    st.rerun()
                
                if c2.button("🚫 Block Device", key=f"mon_block_{row['id']}"):
                    db.set_device_status_by_id(row['id'], "blocked", "user_blocked")
                    st.error("Device Blocked!")
                    time.sleep(1)
                    st.rerun()
        st.markdown("---")

    # --- Live Logs Section ---
    placeholder = st.empty()
    
    while True:
        conn = db.get_connection()
        df = pd.read_sql_query("SELECT timestamp, level, event_type, message FROM logs ORDER BY id DESC LIMIT 20", conn)
        conn.close()
        
        with placeholder.container():
            for index, row in df.iterrows():
                color = "#00ff9d" if row['level'] == "INFO" else "#ff2a6d"
                st.markdown(f"""
                <div style="border-left: 3px solid {color}; padding-left: 10px; margin-bottom: 5px; background: rgba(255,255,255,0.05);">
                    <small style="color: #8b9db5">{row['timestamp']}</small><br>
                    <strong style="color: {color}">[{row['event_type']}]</strong> {row['message']}
                </div>
                """, unsafe_allow_html=True)
        
        time.sleep(2)

def devices_page():
    st.title("🔌 Device Management")
    
    conn = db.get_connection()
    # Fetch alias column if it exists (handled by migration)
    try:
        devices = pd.read_sql_query("SELECT * FROM devices ORDER BY last_seen DESC", conn)
    except Exception:
        st.error("Database schema update required. Please run migration.")
        return
    conn.close()
    
    if devices.empty:
        st.info("No devices found.")
        return

    for index, row in devices.iterrows():
        # Determine display name
        display_name = row['alias'] if row.get('alias') else f"{row['vendor']} {row['product']}"
        
        with st.expander(f"{display_name} ({row['device_id']})"):
            c1, c2 = st.columns(2)
            c1.write(f"**Status:** {row['status']}")
            c1.write(f"**Mount Point:** {row['mount_point']}")
            c2.write(f"**First Seen:** {row['first_seen']}")
            c2.write(f"**Last Seen:** {row['last_seen']}")
            
            st.markdown("---")
            
            # Action Buttons
            col_a, col_b, col_c = st.columns(3)
            
            # Trust/Block
            if col_a.button("Trust Device", key=f"trust_{row['id']}"):
                db.set_device_status_by_id(row['id'], "allowed", "user_approved")
                st.success("Device Trusted!")
                time.sleep(0.5)
                st.rerun()
            
            if col_b.button("Block Device", key=f"block_{row['id']}"):
                db.set_device_status_by_id(row['id'], "blocked", "user_blocked")
                st.error("Device Blocked!")
                time.sleep(0.5)
                st.rerun()
                
            # Delete
            if col_c.button("Delete Device", key=f"del_{row['id']}"):
                db.delete_device(row['id'])
                st.warning("Device Deleted!")
                time.sleep(0.5)
                st.rerun()
            
            # Rename Section
            with st.form(key=f"rename_{row['id']}"):
                new_alias = st.text_input("Rename Device (Alias)", value=row['alias'] if row.get('alias') else "")
                if st.form_submit_button("Save Name"):
                    db.update_device_alias(row['id'], new_alias)
                    st.success(f"Renamed to {new_alias}")
                    time.sleep(0.5)
                    st.rerun()

def logs_page():
    st.title("📜 System Logs")
    conn = db.get_connection()
    df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC LIMIT 500", conn)
    conn.close()
    st.dataframe(df, use_container_width=True)

# --- Main App Logic ---
if not st.session_state.logged_in:
    if st.session_state.page == "Register":
        register_page()
    else:
        login_page()
else:
    # Sidebar
    with st.sidebar:
        st.title("USB Guard")
        st.write(f"User: {st.session_state.user['username']}")
        st.markdown("---")
        
        page = st.radio("Navigation", ["Dashboard", "Live Monitor", "Devices", "Logs"])
        
        st.markdown("---")
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.rerun()
            
    # Page Routing
    if page == "Dashboard":
        main_dashboard()
    elif page == "Live Monitor":
        monitor_page()
    elif page == "Devices":
        devices_page()
    elif page == "Logs":
        logs_page()
