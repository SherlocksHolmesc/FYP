@echo off
echo ==================================
echo   Web3 Risk Guard - Quick Start
echo ==================================
echo.

echo [1/2] Starting Backend API...
start cmd /k "cd backend && python api.py"

timeout /t 3 /nobreak >nul

echo [2/2] Starting Landing Page...
start cmd /k "cd web && npm run dev"

echo.
echo ================================
echo Services starting...
echo ================================
echo Backend API: http://localhost:5000
echo Landing Page: http://localhost:5173
echo.
echo Close the terminal windows to stop services
echo ================================
pause
