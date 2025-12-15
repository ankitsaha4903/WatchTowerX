# Email OTP Setup Guide

## Quick Setup (3 Steps)

### Step 1: Get Gmail App Password
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable **2-Step Verification** (if not already enabled)
3. Go to [App Passwords](https://myaccount.google.com/apppasswords)
4. Select **Mail** and **Windows Computer**
5. Click **Generate**
6. Copy the 16-character password (e.g., `abcd efgh ijkl mnop`)

### Step 2: Update .env File
Open `.env` in your project folder and update:

```env
GMAIL_ADDRESS=your.email@gmail.com
GMAIL_APP_PASSWORD=abcdefghijklmnop
```

**Important**: 
- Use your actual Gmail address
- Use the App Password (NOT your regular Gmail password)
- Remove spaces from the App Password

### Step 3: Restart the App
```bash
# Stop the current app (Ctrl+C)
# Then restart:
streamlit run streamlit_app.py
```

## Testing Email OTP

1. Go to **Create Account** → **Email** tab
2. Enter any email address
3. Click **Send OTP**
4. Check your inbox for the OTP email
5. Enter the OTP and complete registration

## Troubleshooting

### "Gmail authentication failed"
- Double-check your email address in `.env`
- Verify the App Password is correct (no spaces)
- Make sure 2-Step Verification is enabled on your Google account

### "Failed to send email"
- Check your internet connection
- Verify Gmail SMTP is not blocked by firewall
- Try generating a new App Password

### Test Mode
If credentials are not configured, the app will show the OTP on screen (Test Mode) instead of sending an email.

## Security Notes
- **Never share your App Password**
- App Passwords bypass 2-Step Verification, so keep them secure
- You can revoke App Passwords anytime from your Google Account settings
