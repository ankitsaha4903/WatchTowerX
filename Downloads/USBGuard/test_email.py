import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Hardcoded credentials to verify they work
GMAIL_ADDRESS = "ankitgupta4903@gmail.com"
GMAIL_APP_PASSWORD = "fysbppntqvhlwxpt"

def test_email():
    print(f"Testing email with:")
    print(f"User: {GMAIL_ADDRESS}")
    print(f"Pass: {GMAIL_APP_PASSWORD}")
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = GMAIL_ADDRESS
        msg['To'] = GMAIL_ADDRESS  # Send to self
        msg['Subject'] = "Test Email from USB Guard Script"
        msg.attach(MIMEText("If you see this, credentials are working!", 'plain'))

        print("\nConnecting to smtp.gmail.com:465...")
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            print("Connected. Logging in...")
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            print("Logged in successfully!")
            
            print("Sending email...")
            server.send_message(msg)
            print("Email sent successfully!")
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    test_email()
