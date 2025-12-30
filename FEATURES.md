# Web3 Risk Guard - Features & Design

## Landing Page Features

### 1. Hero Section
- **3D Animated Sphere**: Interactive Three.js sphere that responds to mouse movement
- **Gradient Text**: Eye-catching pink-to-blue gradient for emphasis
- **Real-time Stats**:
  - 3,580+ Known Scams Detected
  - 95% Detection Accuracy
  - Real-time Protection
- **CTA Buttons**: "Try Scanner" and "View on GitHub"

### 2. Features Grid
Six key features displayed in card format:
- Multi-Layer Detection
- AI-Powered Analysis
- Real-Time Scanning
- Low False Positives
- Website Verification
- Transaction Analysis

### 3. Security Scanner
**Two Modes:**

#### Address Scanner
- Input: Ethereum address (0x...)
- Output:
  - Risk score (0-100)
  - Prediction (SAFE/FRAUD/SUSPICIOUS)
  - GoPlus flags (honeypot, phishing, etc.)
  - ML model score breakdown
  - Component scores (ML, GoPlus, Heuristic)

#### Website Scanner
- Input: Website URL
- Output:
  - Safety verdict (SAFE/CAUTION/SUSPICIOUS/DANGEROUS)
  - Phishing detection
  - dApp verification status
  - Audit status
  - Contract security flags
  - Malicious contracts detected

### 4. Footer
- Product links
- Resource links
- GitHub repository
- Tech stack credits

## Extension UI Features

### Modern Design Elements

#### Header
- Gradient logo with shield icon
- Active status badge
- Website indicator with pulse animation

#### Score Card
- Large, prominent risk score (64px font)
- Animated gradient background
- Color-coded severity levels:
  - Green (0-29): LOW
  - Yellow (30-59): MEDIUM
  - Orange (60-79): HIGH
  - Red (80-100): CRITICAL

#### Detection Breakdown
- Progress bars for each component:
  - Heuristic detection
  - Blacklist matching
  - ML model prediction
- Real-time score visualization
- Color-coded progress fills

#### Risk Indicators
- Chip-style flag items
- Color-coded by severity
- Clear, concise descriptions

### Animations

#### Landing Page
- Framer Motion scroll animations
- 3D sphere auto-rotation
- Hover effects on cards
- Button hover states with elevation

#### Extension
- Rotating gradient background
- Pulsing active indicator
- Smooth progress bar fills
- Fade-in content transitions

## Design System

### Colors
```css
--bg-dark: #0d0e1a       /* Main background */
--bg-card: #1a1b2e       /* Card backgrounds */
--accent-pink: #ff007a   /* Primary accent */
--accent-blue: #2172e5   /* Secondary accent */
--accent-green: #27ae60  /* Success/safe */
--text-primary: #ffffff  /* Main text */
--text-secondary: #b8b9bf /* Muted text */
--border: #2c2f36        /* Borders */
```

### Typography
- **Font**: System fonts (-apple-system, Segoe UI, Roboto)
- **Headings**: 700-800 weight
- **Body**: 400-600 weight
- **Scale**: 11px - 72px

### Spacing
- Consistent padding: 16px, 20px, 24px, 32px
- Border radius: 12px, 16px, 20px, 24px
- Gaps: 6px, 8px, 12px, 16px, 20px

### Components

#### Buttons
- Primary: Pink-to-blue gradient
- Secondary: Dark background with border
- Hover: Elevation and glow effects

#### Cards
- Dark background (#1a1b2e)
- 1px subtle border
- 24px border radius
- Hover: Border highlight and elevation

#### Badges
- Small, pill-shaped
- Semi-transparent backgrounds
- Colored borders matching content

## User Experience

### Landing Page Flow
1. User lands on hero section
2. Scrolls through features
3. Reaches scanner section
4. Chooses address or website mode
5. Enters input and clicks check
6. Views detailed risk analysis
7. Can check multiple items

### Extension Flow
1. User browses dApp
2. Initiates wallet transaction
3. Extension intercepts request
4. Background.js analyzes in real-time
5. User clicks extension icon
6. Views detailed risk breakdown
7. Makes informed decision

## Technical Highlights

### Landing Page
- **React 18** with Vite for fast development
- **Three.js** via @react-three/fiber
- **Framer Motion** for smooth animations
- **Axios** for API communication
- **Responsive design** for all screen sizes

### Extension
- **Manifest V3** for modern Chrome extensions
- **Real-time monitoring** via injected scripts
- **Hybrid scoring** combining multiple data sources
- **Clean UI** with CSS variables and modern layouts

### Backend Integration
- RESTful API endpoints
- JSON responses
- Error handling
- Loading states
- Graceful fallbacks

## Accessibility

- High contrast colors
- Readable font sizes
- Clear visual hierarchy
- Keyboard navigation support
- Screen reader friendly labels

## Performance

### Landing Page
- Code splitting for faster loads
- Lazy loading for 3D content
- Optimized animations (GPU accelerated)
- Compressed assets

### Extension
- Minimal background script footprint
- Efficient DOM manipulation
- Debounced API calls
- Cached results

## Browser Compatibility

- Chrome 88+
- Edge 88+
- Brave (Chromium-based)
- Any Chromium-based browser

## Security Considerations

- No sensitive data stored locally
- API calls over HTTPS in production
- Input validation on all user inputs
- XSS protection
- Content Security Policy compliant

## Future Enhancements

Potential improvements:
- Dark/light mode toggle
- More 3D models and animations
- Transaction history in extension
- Whitelist management
- Mobile browser support
- Additional blockchain support (Polygon, BSC)
- Browser notifications for high-risk sites
- Export risk reports
