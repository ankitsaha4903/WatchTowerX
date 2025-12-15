# HTTPS Configuration Guide

## Overview
The USB Guard application is now configured to run on HTTPS at `https://192.168.150.47:5000`

## What Changed

### 1. SSL Certificates Generated
- **cert.pem**: Self-signed SSL certificate valid for 1 year
- **key.pem**: Private key for SSL encryption
- **Certificate CN**: 192.168.150.47

### 2. Flask Configuration Updated
**File**: `dashboard.py`

```python
if __name__ == "__main__":
    app.run(
        host='192.168.150.47',  # Network IP address
        port=5000,
        debug=True,
        threaded=True,
        ssl_context=('cert.pem', 'key.pem')  # SSL certificates
    )
```

## Accessing the Application

### From This Computer:
- **HTTPS**: `https://192.168.150.47:5000`
- **HTTP (old)**: No longer works

### From Other Devices on Network:
1. Ensure devices are on the same network
2. Navigate to: `https://192.168.150.47:5000`
3. **Accept the security warning** (self-signed certificate)

## Browser Security Warning

Since we're using a self-signed certificate, browsers will show a security warning:

### Chrome/Edge:
1. Click "Advanced"
2. Click "Proceed to 192.168.150.47 (unsafe)"

### Firefox:
1. Click "Advanced"
2. Click "Accept the Risk and Continue"

## Firewall Configuration

If you can't access from other devices, you may need to allow the port:

```powershell
# Run as Administrator
New-NetFirewallRule -DisplayName "USB Guard HTTPS" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

## Security Notes

> [!IMPORTANT]
> - This is a **self-signed certificate** - browsers will show warnings
> - For production, use a certificate from a trusted CA (Let's Encrypt, etc.)
> - The certificate is valid for 1 year from generation date

> [!WARNING]
> - All traffic is encrypted with SSL/TLS
> - Self-signed certificates don't verify identity, only encrypt data
> - Users must manually accept the certificate

## Regenerating Certificates

If you need to regenerate certificates (e.g., after expiry):

```bash
python generate_cert.py
```

Then restart the dashboard:
```bash
python dashboard.py
```

## Troubleshooting

### Can't Access from Other Devices
1. Check firewall settings
2. Verify IP address: `ipconfig` (should show 192.168.150.47)
3. Ensure devices are on same network
4. Try pinging: `ping 192.168.150.47`

### Certificate Errors
- Normal for self-signed certificates
- Users must manually accept the warning
- For production, get a proper SSL certificate

### Port Already in Use
```bash
# Find process using port 5000
netstat -ano | findstr :5000

# Kill the process (replace PID)
taskkill /PID <PID> /F
```

## Files Created
- `cert.pem` - SSL certificate
- `key.pem` - Private key
- `generate_cert.py` - Certificate generation script

## Next Steps (Optional)

### For Production Use:
1. Get a proper domain name
2. Use Let's Encrypt for free SSL certificate
3. Set up proper DNS
4. Use a production WSGI server (Gunicorn, uWSGI)
5. Set `debug=False` in production
