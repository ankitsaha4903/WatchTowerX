@echo off
echo ========================================
echo WatchTowerX - Quick Deployment Script
echo ========================================
echo.

echo Step 1: Pushing code to GitHub...
echo.
git push origin main
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Failed to push to GitHub!
    echo Please make sure you're logged into GitHub.
    echo You may need to authenticate via browser.
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo SUCCESS! Code pushed to GitHub
echo ========================================
echo.
echo Next Steps:
echo 1. Go to: https://dashboard.render.com/
echo 2. Sign in with GitHub (browser should be open)
echo 3. Click "New +" then "Web Service"
echo 4. Select repository: ankitsaha4903/WatchTowerX
echo 5. Render will auto-detect render.yaml and deploy!
echo.
echo Your app will be live at: https://watchtowerx-XXXX.onrender.com
echo (Deployment takes 5-10 minutes)
echo.
pause
