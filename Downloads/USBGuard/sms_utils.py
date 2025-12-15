import os
import random
from twilio.rest import Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def send_otp(phone_number):
    """
    Generates a 6-digit OTP and sends it via Twilio SMS.
    Returns the OTP if successful, or None if failed.
    """
    # Force reload environment variables to pick up changes
    load_dotenv(override=True)
    
    account_sid = os.getenv('TWILIO_ACCOUNT_SID')
    auth_token = os.getenv('TWILIO_AUTH_TOKEN')
    twilio_phone = os.getenv('TWILIO_PHONE_NUMBER')

    if not all([account_sid, auth_token, twilio_phone]):
        return None, "Twilio credentials missing in .env"

    # Check for placeholders (ignoring quotes if present)
    sid_check = account_sid.replace('"', '').replace("'", "")
    token_check = auth_token.replace('"', '').replace("'", "")
    
    if "your_" in sid_check or "your_" in token_check:
        # Fallback to Test Mode
        otp = str(random.randint(100000, 999999))
        print(f"[TEST MODE] Generated OTP: {otp}")
        return otp, "TEST_MODE"

    try:
        client = Client(account_sid, auth_token)
        otp = str(random.randint(100000, 999999))
        
        message = client.messages.create(
            body=f"Your USB Guard OTP is: {otp}",
            from_=twilio_phone,
            to=phone_number
        )
        return otp, None
    except Exception as e:
        # Clean up error message (remove ANSI codes if present)
        error_msg = str(e)
        import re
        clean_error = re.sub(r'\x1b\[[0-9;]*m', '', error_msg)
        
        # Check for specific user configuration errors
        if "is not a Twilio phone number" in clean_error:
            print(f"Twilio Config Error: {clean_error}")
            return None, "⚠️ Configuration Error: The 'TWILIO_PHONE_NUMBER' in your .env file is incorrect. It must be the number provided by Twilio (Trial Number), NOT your personal number."
            
        print(f"Twilio Error: {clean_error}")
        return None, f"Twilio API Error: {clean_error}"
