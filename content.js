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
}
