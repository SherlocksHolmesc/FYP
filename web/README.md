# Web3 Risk Guard - Landing Page

Modern landing page for the Web3 Risk Guard browser extension with integrated security scanner.

## Features

- 3D animated hero section with Three.js
- Interactive address and website scanner
- Real-time risk analysis via backend API
- Responsive Uniswap-inspired design
- Framer Motion animations

## Setup

1. Install dependencies:
```bash
npm install
```

2. Make sure the backend API is running:
```bash
cd ../backend
python api.py
```

3. Start the development server:
```bash
npm run dev
```

4. Build for production:
```bash
npm run build
```

## Usage

- Visit the landing page to learn about Web3 Risk Guard
- Use the scanner to check Ethereum addresses or websites
- The scanner connects to the backend API at `http://localhost:5000`

## Tech Stack

- React 18
- Vite
- Three.js & React Three Fiber
- Framer Motion
- Axios
