# Testing Proactive Simulation Feature

## ✅ What Was Implemented

### Phase 1: Proactive Simulation with Chrome Notifications

**New Files Modified:**

- `background.js` - Added simulation cache, `checkSimulation()`, notification logic
- `content.js` - Added PAGE_LOADED message for background cache warming
- `popup.js` - Display simulation results in popup
- `popup.html` - Added CSS for blocked badge and text colors
- `manifest.json` - Added `notifications` permission (v0.3.0)

## 🚀 How It Works

### Flow 1: Wallet Interaction (Blocking)

```
User clicks "Connect Wallet" or "Sign"
  ↓
background.js intercepts WALLET_REQUEST
  ↓
Calls /simulate-dapp?url=<current_page_url>
  ↓
IF is_malicious === true && confidence >= 85%:
  ✓ Show Chrome notification (⚠️ DANGER)
  ✓ Block transaction
  ✓ Set score to 100 (CRITICAL)
  ✓ Store blocked=true in latestByTab
ELSE:
  ✓ Continue with normal ML + darklist scoring
  ✓ Attach simulation result to analysis
```

### Flow 2: Page Load (Background Cache Warming)

```
User navigates to any website
  ↓
content.js sends PAGE_LOADED message
  ↓
background.js silently calls checkSimulation()
  ↓
Result cached for 5 minutes
  ↓
IF confidence >= 95% && typosquatting_detected:
  ✓ Show notification immediately (before user interacts)
```

## 🧪 Testing Instructions

### Step 1: Reload Extension

1. Open `chrome://extensions`
2. Find "Web3 Risk Guard (MVP)"
3. Click reload button (or remove and re-add unpacked extension)
4. Check version shows **0.3.0**

### Step 2: Verify Simulation Cache Warming

1. Make sure backend is running (`python backend/api.py`)
2. Navigate to ANY website (e.g., `https://app.uniswap.org`)
3. Open Browser Console (F12)
4. Look for `[W3RG]` logs:
   ```
   [W3RG] Page loaded - background simulation check initiated
   [W3RG] Simulation result: SAFE (98% confidence)
   ```

### Step 3: Test Legitimate Site (No Notification)

1. Visit `https://app.uniswap.org`
2. Click "Connect Wallet" button
3. **Expected**:
   - No notification shown (safe site)
   - MetaMask prompt appears normally
   - Extension popup shows simulation result:
     ```
     dApp Simulation: ✓ SAFE
     Confidence: 98%
     ```

### Step 4: Test Malicious Site (With Notification)

**Option A: Create a Test Malicious Site**

1. Modify `backend/dapp_simulator.py` to mark a test domain as malicious:

   ```python
   # Add to simulate_dapp function (for testing only)
   if 'test-scam.local' in url.lower():
       return {
           'is_malicious': True,
           'confidence': 95,
           'typosquatting_detected': True,
           'similar_to': 'uniswap.org'
       }
   ```

2. Add `127.0.0.1 test-scam.local` to your `C:\Windows\System32\drivers\etc\hosts`

3. Visit `http://test-scam.local`

**Expected Behavior**:

- **Chrome notification pops up**:

  ```
  🚨 DANGER - Suspected Scam Detected!
  This website appears to be malicious (95% confidence).

  ⚠️ Typosquatting detected!
  Did you mean: uniswap.org?
  ```

- Click "Connect Wallet" → **Transaction BLOCKED**
- Extension popup shows:

  ```
  Risk Score: 100 (CRITICAL)
  🚨 BLOCKED

  dApp Simulation: ⚠️ MALICIOUS
  Confidence: 95%
  ⚠️ Typosquatting: Similar to uniswap.org
  ```

### Step 5: Test Typosquatting Detection

Try these known typosquatting patterns:

- `uniiswap.org` (extra 'i')
- `unisvvap.org` (vv instead of w)
- `app-uniswap.org` (extra dash)

Your `dapp_simulator.py` should detect these if implemented.

## 📊 Expected Console Logs

### Background.js Logs

```javascript
[W3RG] Darklist loaded: 3580 addresses
[W3RG] Page loaded - background simulation check initiated
[W3RG] Simulation result: SAFE (98% confidence)
[W3RG] Simulation from cache: https://app.uniswap.org
```

When malicious detected:

```javascript
[W3RG] Simulation result: MALICIOUS (95% confidence)
[W3RG] 🚨 BLOCKING malicious wallet request on http://test-scam.local
[W3RG] 🚨 Danger notification shown for test-scam.local
```

### Backend Logs

```
[DEBUG] Simulating dApp: https://app.uniswap.org
[DEBUG] Typosquatting check: app.uniswap.org vs legit brands
[DEBUG] No typosquatting detected
[DEBUG] Simulation complete: SAFE (confidence: 98)
```

## 🎯 Key Features

### 1. Smart Caching (5-minute TTL)

- Simulation runs once per domain
- Cached results reused for all wallet interactions
- Reduces API load and latency

### 2. Fail-Open Design

- If simulation API times out → don't block (UX > security for edge cases)
- Only shows notifications for HIGH confidence (>= 85%)
- User still sees risk score in popup

### 3. Adaptive Notifications

- **Confidence >= 95% + Typosquatting**: Show notification on page load
- **Confidence >= 85%**: Show notification on wallet interaction
- **Confidence < 85%**: No notification (rely on ML + darklist)

### 4. Popup Enhancements

- Shows simulation status (SAFE/MALICIOUS)
- Displays confidence percentage
- Shows typosquatting info with "Similar to:" hint
- **Blocked badge** pulses when transaction is blocked

## 🐛 Troubleshooting

### Notification Not Showing

**Check 1**: Chrome notifications enabled?

- Go to `chrome://settings/content/notifications`
- Ensure notifications are allowed

**Check 2**: Extension has permission?

- Check `manifest.json` has `"notifications"` in `permissions`
- Reload extension

**Check 3**: Simulation API working?

```powershell
Invoke-RestMethod "http://localhost:5000/simulate-dapp?url=https://app.uniswap.org"
```

### Transaction Not Blocked

**Check 1**: Confidence threshold

- Simulation must return `confidence >= 85` to block
- Check backend logs for actual confidence value

**Check 2**: `is_malicious` flag

- Must be `true` in simulation response
- Verify `dapp_simulator.py` logic

### Popup Not Showing Simulation

**Check 1**: Data structure

- Open popup DevTools (right-click popup → Inspect)
- Check console for errors
- Verify `data.analysis.simulation` exists

## 🔄 Next Steps (Future Enhancements)

### Phase 2: Visual Page Overlay

Add red warning banner at top of page when malicious site detected.

### Phase 3: User Override

Allow power users to proceed despite warning (with confirmation dialog).

### Phase 4: Confidence-Based Notifications

- 95-100%: CRITICAL (red, must dismiss)
- 85-94%: WARNING (orange, auto-dismiss after 10s)
- 70-84%: INFO (yellow, show in popup only)

## 📝 Performance Notes

- **Simulation API timeout**: 15 seconds (vs 8s for ML API)
- **Cache TTL**: 5 minutes (same as ML cache)
- **Network overhead**: ~1 additional API call per domain visit
- **User experience**: Near-zero latency on cached results

---

**Version**: 0.3.0
**Date**: January 6, 2026
**Status**: ✅ Implemented and Ready for Testing
