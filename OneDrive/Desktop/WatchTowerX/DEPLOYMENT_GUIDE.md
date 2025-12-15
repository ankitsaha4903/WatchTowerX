# WatchTowerX Deployment Guide

## Quick Deployment to Render.com (FREE)

### Prerequisites
✅ Your local server is running at http://localhost:8000
✅ Code is ready for deployment
✅ GitHub repository exists at: https://github.com/ankitsaha4903/WatchTowerX

### Step 1: Push Code to GitHub

You need to push the latest changes to your GitHub repository. Please run these commands:

```bash
# Login to GitHub (if not already logged in)
# You may need to authenticate via browser

# Push the changes
git push origin main
```

If you get permission errors, you'll need to:
1. Go to https://github.com/login
2. Sign in with your credentials
3. Then try pushing again

### Step 2: Deploy to Render.com

1. **Go to Render Dashboard**: https://dashboard.render.com/
   
2. **Sign in with GitHub**:
   - Click "Sign in with GitHub"
   - Authorize Render to access your repositories

3. **Create New Web Service**:
   - Click "New +" button → "Web Service"
   - Connect your GitHub repository: `ankitsaha4903/WatchTowerX`
   - Click "Connect"

4. **Configure the Service**:
   - **Name**: `watchtowerx` (or any name you prefer)
   - **Region**: Choose closest to you (e.g., Oregon, Singapore)
   - **Branch**: `main`
   - **Runtime**: Docker
   - **Plan**: Free
   
5. **Click "Create Web Service"**

6. **Wait for Deployment** (5-10 minutes):
   - Render will automatically:
     - Pull your code from GitHub
     - Build the Docker image
     - Deploy the application
     - Assign a public URL

7. **Get Your Live URL**:
   - Once deployed, you'll see: `https://watchtowerx-XXXX.onrender.com`
   - This URL is permanent and accessible from anywhere!

### Alternative: Use the render.yaml file

I've already created a `render.yaml` file in your project. When you connect the repository to Render, it will automatically detect this file and configure everything for you!

### Troubleshooting

**If deployment fails:**
- Check the Render logs for errors
- Ensure all dependencies are in `requirements.txt`
- Verify the Dockerfile is correct

**If you see "Service Unavailable":**
- Wait a few minutes - Render free tier can take time to start
- The first request might be slow as it spins up the server

### Your Files Are Ready!
✅ `Dockerfile` - Fixed and ready
✅ `render.yaml` - Render configuration
✅ `main.py` - Application entry point
✅ `requirements.txt` - Dependencies

---

## Need Help?

If you encounter any issues during deployment, let me know and I'll help you troubleshoot!
