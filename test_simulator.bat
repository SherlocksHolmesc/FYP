@echo off
echo ========================================
echo Testing Honeypot Simulator
echo ========================================
echo.
echo Make sure Ganache is running in another terminal!
echo (Run: start_ganache.bat)
echo.
pause
echo.
echo Running simulator tests...
echo.
cd backend
python honeypot_simulator.py
pause
