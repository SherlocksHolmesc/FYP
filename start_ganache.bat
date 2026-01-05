@echo off
echo ========================================
echo Starting Ganache Fork
echo ========================================
echo.
echo STEP 1: Get your Alchemy API key from .env
for /f "tokens=2 delims==" %%a in ('findstr /B "ALCHEMY_API_KEY" backend\.env 2^>nul') do set ALCHEMY_KEY=%%a

if "%ALCHEMY_KEY%"=="" (
    echo [ERROR] ALCHEMY_API_KEY not found in backend\.env
    echo.
    echo Please:
    echo 1. Get free key from: https://www.alchemy.com/
    echo 2. Edit backend\.env and replace: your_alchemy_key_here
    echo 3. Run this script again
    pause
    exit /b 1
)

if "%ALCHEMY_KEY%"=="your_alchemy_key_here" (
    echo [ERROR] Please replace 'your_alchemy_key_here' with your actual Alchemy API key
    echo.
    echo 1. Get free key from: https://www.alchemy.com/
    echo 2. Edit backend\.env
    pause
    exit /b 1
)

echo [OK] Found Alchemy API key
echo.
echo STEP 2: Starting Ganache fork on port 8545...
echo This will create a local copy of Ethereum mainnet
echo Press Ctrl+C to stop
echo.
ganache --fork https://eth-mainnet.g.alchemy.com/v2/%ALCHEMY_KEY% --port 8545 --chain.chainId 1
