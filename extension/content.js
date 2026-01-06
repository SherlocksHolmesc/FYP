// Inject inpage.js into the page context (so it can access window.ethereum)
const s = document.createElement("script");
s.src = chrome.runtime.getURL("inpage.js");
s.onload = () => s.remove();
(document.head || document.documentElement).appendChild(s);

// Receive intercepted wallet requests from inpage.js
window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const msg = event.data;
  if (!msg || msg.__W3RG__ !== true) return;

  chrome.runtime.sendMessage({
    type: "WALLET_REQUEST",
    payload: msg.payload,
  });
});

// ============================================================
// PROACTIVE SIMULATION - Run on page load
// ============================================================
// This pre-populates the simulation cache before user interacts
// Only runs on http/https pages to avoid unnecessary checks
if (
  window.location.protocol === "http:" ||
  window.location.protocol === "https:"
) {
  chrome.runtime.sendMessage({
    type: "PAGE_LOADED",
    url: window.location.href,
  });

  console.log("[W3RG] Page loaded - background simulation check initiated");

  // Listen for simulation result to show on-page banner
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "SHOW_BANNER") {
      showSecurityBanner(msg.data);
    }
  });
}

// ============================================================
// ON-PAGE SECURITY BANNER
// ============================================================
function showSecurityBanner(data) {
  // Remove existing banner if any
  const existing = document.getElementById("w3rg-security-banner");
  if (existing) existing.remove();

  const { is_malicious, confidence, typosquatting_detected, similar_to } = data;

  // Don't show banner for low confidence
  if (confidence < 80) return;

  console.log("[W3RG] 🎨 Creating on-page banner:", data);

  const banner = document.createElement("div");
  banner.id = "w3rg-security-banner";

  // Styling - VERY forceful to override any website CSS
  banner.style.cssText = `
    position: fixed !important;
    top: 20px !important;
    right: 20px !important;
    z-index: 2147483647 !important;
    padding: 18px 22px !important;
    border-radius: 12px !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    font-size: 14px !important;
    font-weight: 500 !important;
    box-shadow: 0 10px 40px rgba(0,0,0,0.15), 0 2px 8px rgba(0,0,0,0.1) !important;
    min-width: 320px !important;
    max-width: 420px !important;
    animation: w3rgSlideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) !important;
    cursor: pointer !important;
    display: block !important;
    opacity: 1 !important;
    visibility: visible !important;
    backdrop-filter: blur(10px) !important;
    transition: transform 0.2s ease, box-shadow 0.2s ease !important;
    ${
      is_malicious
        ? "background: linear-gradient(135deg, rgba(254, 226, 226, 0.95), rgba(254, 202, 202, 0.95)) !important; color: #991b1b !important; border: 1px solid rgba(239, 68, 68, 0.4) !important;"
        : "background: linear-gradient(135deg, rgba(52, 211, 153, 0.12), rgba(16, 185, 129, 0.08)) !important; color: #047857 !important; border: 1px solid rgba(52, 211, 153, 0.3) !important; backdrop-filter: blur(20px) saturate(180%) !important;"
    }
  `;

  // Content
  banner.innerHTML = `
    <div style="display: flex !important; flex-direction: column !important; gap: 12px !important;">
      <!-- URL Being Checked -->
      <div style="display: flex !important; align-items: center !important; gap: 8px !important; padding: 8px 12px !important; background: ${is_malicious ? 'rgba(153,27,27,0.1)' : 'rgba(255,255,255,0.5)'} !important; border-radius: 6px !important; font-size: 11px !important; font-family: 'JetBrains Mono', monospace !important;">
        <span style="opacity: 0.7 !important;">🔗</span>
        <span style="overflow: hidden !important; text-overflow: ellipsis !important; white-space: nowrap !important; ${is_malicious ? 'color: #7f1d1d' : 'color: #065f46'} !important; font-weight: 500 !important;">${data.url || window.location.hostname}</span>
      </div>
      
      <!-- Main Content -->
      <div style="display: flex !important; align-items: start !important; gap: 16px !important;">
        <div style="font-size: 36px !important; line-height: 1 !important; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.15)) !important;">
          ${is_malicious ? "🚨" : "🛡️"}
        </div>
        <div style="flex: 1 !important;">
          <div style="font-size: 16px !important; font-weight: 700 !important; margin-bottom: 4px !important; letter-spacing: -0.02em !important; ${is_malicious ? 'color: #991b1b' : 'color: #047857'} !important;">
            ${is_malicious ? "⚠️ Suspected Scam" : "✔️ Verified Safe"}
          </div>
          <div style="font-size: 13px !important; font-weight: 400 !important; line-height: 1.5 !important; ${is_malicious ? 'color: #b91c1c' : 'color: #059669; opacity: 0.85'} !important;">
            ${is_malicious 
              ? `This website shows malicious patterns` 
              : `No security threats detected`
            }
          </div>
          <div style="margin-top: 8px !important; display: flex !important; align-items: center !important; gap: 6px !important; font-size: 12px !important; font-weight: 600 !important; ${is_malicious ? 'color: #dc2626' : 'color: #10b981'} !important;">
            <div style="width: 32px !important; height: 4px !important; background: ${is_malicious ? 'rgba(220,38,38,0.2)' : 'rgba(16,185,129,0.3)'} !important; border-radius: 2px !important; overflow: hidden !important;">
              <div style="width: ${confidence}% !important; height: 100% !important; background: ${is_malicious ? '#dc2626' : '#10b981'} !important; transition: width 0.3s ease !important;"></div>
            </div>
            <span>${confidence}%</span>
          </div>
        </div>
      </div>
      
      ${typosquatting_detected ? `
        <div style="margin-top: 4px !important; font-size: 12px !important; background: rgba(239,68,68,0.1) !important; padding: 10px 12px !important; border-radius: 6px !important; border-left: 3px solid #ef4444 !important; color: #991b1b !important;">
          <div style="font-weight: 600 !important; margin-bottom: 4px !important;">⚠️ Typosquatting Alert</div>
          <div style="opacity: 0.9 !important;">Did you mean: <strong>${similar_to}</strong>?</div>
        </div>
      ` : ''}
      
      <!-- Footer -->
      <div style="margin-top: 4px !important; padding-top: 12px !important; border-top: 1px solid ${is_malicious ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)'} !important; display: flex !important; align-items: center !important; justify-content: space-between !important;">
        <div style="font-size: 11px !important; font-weight: 500 !important; ${is_malicious ? 'color: #b91c1c; opacity: 0.7' : 'color: #10b981; opacity: 0.6'} !important; letter-spacing: 0.02em !important;">
          🛡️ GuardChain
        </div>
        <div style="font-size: 11px !important; font-weight: 600 !important; ${is_malicious ? 'color: #dc2626' : 'color: #059669'} !important; text-transform: uppercase !important; letter-spacing: 0.05em !important;">
          Click Extension Icon →
        </div>
      </div>
    </div>
  `;

  // Add animation keyframes and hover effect
  if (!document.getElementById("w3rg-banner-styles")) {
    const style = document.createElement("style");
    style.id = "w3rg-banner-styles";
    style.textContent = `
      @keyframes w3rgSlideIn {
        from {
          transform: translateX(450px) scale(0.9) !important;
          opacity: 0 !important;
        }
        to {
          transform: translateX(0) scale(1) !important;
          opacity: 1 !important;
        }
      }
      @keyframes w3rgSlideOut {
        from {
          transform: translateX(0) scale(1) !important;
          opacity: 1 !important;
        }
        to {
          transform: translateX(450px) scale(0.9) !important;
          opacity: 0 !important;
        }
      }
      #w3rg-security-banner:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 12px 48px rgba(0,0,0,0.2), 0 4px 12px rgba(0,0,0,0.15) !important;
      }
    `;
    document.head.appendChild(style);
  }

  // Click to dismiss banner (Chrome security prevents opening popup programmatically)
  banner.addEventListener("click", () => {
    console.log('[W3RG] Banner clicked - dismissing (user should click extension icon for details)');
    banner.style.animation = "w3rgSlideOut 0.3s ease-out forwards !important";
    setTimeout(() => banner.remove(), 300);
  });

  // Auto-dismiss safe banners after 10 seconds
  if (!is_malicious) {
    setTimeout(() => {
      if (banner.parentNode) {
        banner.style.animation =
          "w3rgSlideOut 0.3s ease-out forwards !important";
        setTimeout(() => banner.remove(), 300);
      }
    }, 10000);
  }

  // Ensure it's added to body (wait for DOM if needed)
  const addBanner = () => {
    if (document.body) {
      document.body.appendChild(banner);
      console.log("[W3RG] ✅ Banner added to page");
    } else {
      setTimeout(addBanner, 100);
    }
  };

  addBanner();
}
