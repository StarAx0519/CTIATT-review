@echo off
cd /d "%~dp0"

if not exist ".env" (
  if exist ".env.example" (
    copy /Y ".env.example" ".env" >nul
    echo [INFO] Created .env from .env.example
  )
)

for /f "tokens=5" %%p in ('netstat -ano ^| findstr /R /C:":3100 .*LISTENING"') do (
  echo [INFO] Port 3100 in use by PID %%p - stopping it
  taskkill /F /PID %%p >nul 2>&1
)

cd backend
if not exist "node_modules\" (
  echo [INFO] Running npm install ...
  call npm install
  if errorlevel 1 (
    echo [ERROR] npm install failed
    pause
    exit /b 1
  )
)

echo.
echo [START] http://127.0.0.1:3100
echo [HINT] Close this window to stop
echo.
node app.js
if errorlevel 1 (
  echo [ERROR] node app.js failed
  pause
  exit /b 1
)
pause
