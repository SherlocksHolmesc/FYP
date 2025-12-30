#!/bin/bash

echo "=================================="
echo "  Web3 Risk Guard - Quick Start"
echo "=================================="
echo ""

# Check if backend dependencies are installed
if [ ! -d "backend/venv" ]; then
    echo "[1/4] Setting up Python virtual environment..."
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    cd ..
else
    echo "[1/4] Python environment ready ✓"
fi

# Check if web dependencies are installed
if [ ! -d "web/node_modules" ]; then
    echo "[2/4] Installing web dependencies..."
    cd web
    npm install
    cd ..
else
    echo "[2/4] Web dependencies ready ✓"
fi

# Check .env file
if [ ! -f "backend/.env" ]; then
    echo "[3/4] Creating .env file..."
    echo "ETHERSCAN_API_KEY=your_api_key_here" > backend/.env
    echo "⚠️  Please add your Etherscan API key to backend/.env"
else
    echo "[3/4] Environment file ready ✓"
fi

echo "[4/4] Starting services..."
echo ""
echo "Starting Backend API on http://localhost:5000"
echo "Starting Landing Page on http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Start backend in background
cd backend
source venv/bin/activate 2>/dev/null || true
python api.py &
BACKEND_PID=$!
cd ..

# Give backend time to start
sleep 3

# Start web dev server
cd web
npm run dev &
WEB_PID=$!
cd ..

# Wait for Ctrl+C
trap "kill $BACKEND_PID $WEB_PID 2>/dev/null; echo ''; echo 'Services stopped.'; exit 0" INT

# Keep script running
wait
