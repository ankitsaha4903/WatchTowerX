import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def send_otp_email(recipient_email):
    """
    Generates a 6-digit OTP and sends it via Gmail SMTP.
    Returns (otp, error_message) tuple.
    - If successful: (otp_string, None)
    - If failed: (None, error_message)
    """
    # Force reload environment variables
    load_dotenv(override=True)
    
    # Direct file read fallback to ensure we get the latest values
    try:
        with open('.env', 'r') as f:
            for line in f:
                if line.startswith('GMAIL_ADDRESS='):
                    os.environ['GMAIL_ADDRESS'] = line.split('=')[1].strip()
                elif line.startswith('GMAIL_APP_PASSWORD='):
                    os.environ['GMAIL_APP_PASSWORD'] = line.split('=')[1].strip()
    except Exception:
        pass
    
    sender_email = os.getenv('GMAIL_ADDRESS')
    app_password = os.getenv('GMAIL_APP_PASSWORD')
    
    print(f"[DEBUG] Attempting to send email from: {sender_email}")
    
    # Check for credentials
    if not sender_email or not app_password:
        return None, "Gmail credentials missing in .env file"
    
    # Check for placeholder values
    if "your_" in sender_email.lower() or "your_" in app_password.lower():
        # Fallback to Test Mode
        otp = str(random.randint(100000, 999999))
        print(f"[TEST MODE] Generated OTP: {otp}")
        return otp, "TEST_MODE"
    
    try:
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        
        # Create email message
        message = MIMEMultipart("alternative")
        message["Subject"] = "USB Guard - Your OTP Code"
        message["From"] = sender_email
        message["To"] = recipient_email
        
        # HTML email body
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #0a0015; color: #e0f7ff; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #1a0033 0%, #0f0028 100%); border: 2px solid #00f3ff; border-radius: 12px; padding: 30px;">
                    <h1 style="color: #00f3ff; text-align: center; text-transform: uppercase; letter-spacing: 2px;">
                        🛡️ USB Guard
                    </h1>
                    <p style="font-size: 16px; line-height: 1.6; color: #cbd5e1;">
                        Hello,
                    </p>
                    <p style="font-size: 16px; line-height: 1.6; color: #cbd5e1;">
                        Your One-Time Password (OTP) for USB Guard registration is:
                    </p>
                    <div style="background: rgba(0, 243, 255, 0.1); border: 2px solid #00f3ff; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
                        <h2 style="color: #00f3ff; font-size: 36px; letter-spacing: 8px; margin: 0;">
                            {otp}
                        </h2>
                    </div>
                    <p style="font-size: 14px; line-height: 1.6; color: #94a3b8;">
                        This OTP is valid for this session only. Do not share this code with anyone.
                    </p>
                    <p style="font-size: 14px; line-height: 1.6; color: #94a3b8;">
                        If you did not request this code, please ignore this email.
                    </p>
                    <hr style="border: none; border-top: 1px solid rgba(0, 243, 255, 0.3); margin: 20px 0;">
                    <p style="font-size: 12px; color: #64748b; text-align: center;">
                        USB Guard Security System<br>
                        This is an automated message, please do not reply.
                    </p>
                </div>
            </body>
        </html>
        """
        
        # Attach HTML body
        html_part = MIMEText(html_body, "html")
        message.attach(html_part)
        
        # Connect to Gmail SMTP server
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, app_password)
            server.send_message(message)
        
        print(f"[EMAIL] OTP sent to {recipient_email}")
        return otp, None
        
    except smtplib.SMTPAuthenticationError:
        error_msg = "Gmail authentication failed. Please check your email and App Password in .env file."
        print(f"[EMAIL ERROR] {error_msg}")
        return None, error_msg
        
    except Exception as e:
        error_msg = f"Failed to send email: {str(e)}"
        print(f"[EMAIL ERROR] {error_msg}")
        return None, error_msg
