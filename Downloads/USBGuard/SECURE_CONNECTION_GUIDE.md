# Secure Connection Guide (Green Lock)

## Overview
To establish a fully trusted HTTPS connection (green lock) on `https://192.168.150.47:5000` from any device, you must install the **Root CA Certificate** (`rootCA.pem`) on that device.

## Step 1: Transfer the Certificate
Transfer the `rootCA.pem` file from your computer to the target device (via USB, email, cloud storage, etc.).

## Step 2: Install Certificate on Devices

### 🖥️ Windows
1. Double-click `rootCA.pem`.
2. Click **Install Certificate**.
3. Select **Local Machine** -> Next.
4. Select **Place all certificates in the following store**.
5. Click **Browse** and select **Trusted Root Certification Authorities**.
6. Click OK -> Next -> Finish.
7. Restart your browser.

### 📱 Android
1. Transfer `rootCA.pem` to phone storage.
2. Go to **Settings** -> **Security** -> **Encryption & Credentials**.
3. Tap **Install a certificate** -> **CA certificate**.
4. Tap **Install anyway** (ignore warning).
5. Select the `rootCA.pem` file.
6. Enter your PIN/Pattern if asked.
7. Restart Chrome.

### 🍎 iOS (iPhone/iPad)
1. AirDrop or email `rootCA.pem` to the device.
2. Tap to install -> **Allow** download profile.
3. Go to **Settings** -> **Profile Downloaded** -> **Install**.
4. **CRITICAL STEP**: Go to **Settings** -> **General** -> **About** -> **Certificate Trust Settings**.
5. Toggle ON for **USB Guard Root CA**.
6. Restart Safari.

### 💻 macOS
1. Double-click `rootCA.pem` to open Keychain Access.
2. Find **USB Guard Root CA** in the list.
3. Double-click it -> Expand **Trust**.
4. Set **When using this certificate** to **Always Trust**.
5. Close window and enter password.
6. Restart browser.

### 🐧 Linux (Ubuntu/Debian)
```bash
sudo cp rootCA.pem /usr/local/share/ca-certificates/usbguard.crt
sudo update-ca-certificates
```

## Step 3: Verify Connection
1. Open browser on the device.
2. Go to `https://192.168.150.47:5000`.
3. You should see the **Green Lock** icon.
4. No security warnings should appear.

## Troubleshooting
- **Still seeing warning?** Ensure you installed into the **Trusted Root** store, not just "Personal".
- **Android Chrome issue?** Ensure the certificate has SAN (Subject Alternative Name) - our script does this automatically.
- **Firefox?** Firefox has its own certificate store. Go to Settings -> Privacy & Security -> Certificates -> View Certificates -> Import -> Select `rootCA.pem` -> Trust this CA to identify websites.
