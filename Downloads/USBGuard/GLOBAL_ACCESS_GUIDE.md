# Global Secure Access Guide

## Overview
Your USB Guard dashboard is now **globally accessible** via a secure, trusted HTTPS connection provided by **Ngrok**.

## How to Access
1.  Look at the terminal/console output where `dashboard.py` is running.
2.  Find the line that looks like:
    ```
    GLOBAL ACCESS URL: https://xxxx-xxxx-xxxx.ngrok-free.app
    ```
3.  **Copy this URL** and send it to any device (Phone, Laptop, Tablet).
4.  Open the link. You will see the **Green Lock** automatically.

## No Installation Required
Unlike the previous method, **you do NOT need to install any certificates** on your devices. The Ngrok URL is trusted by all browsers (Chrome, Safari, Edge) out of the box.

## Important Notes
- **Dynamic URL**: If you are using the free version of Ngrok, this URL will change every time you restart the application.
- **Ngrok Warning**: When you first visit the link, Ngrok might show a "Visit Site" warning page. Just click "Visit Site" to proceed.
- **Account (Optional)**: For a stable URL and to remove the warning page, create a free account at [ngrok.com](https://ngrok.com) and run:
  ```bash
  ngrok config add-authtoken <YOUR_TOKEN>
  ```

## Troubleshooting
- **Link not working?** Ensure `dashboard.py` is running on your computer.
- **"Tunnel not found"?** You might have restarted the app, generating a new link. Check the console for the new URL.
