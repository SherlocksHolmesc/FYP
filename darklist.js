/**
 * Darklist Lookup Module
 *
 * Checks if an address is in the known scam/phishing blacklist.
 * Data source: MyEtherWallet ethereum-lists
 */

// This will be populated from darklist.json
let DARKLIST = new Set();
let DARKLIST_INFO = new Map();

// Load darklist on startup
async function loadDarklist() {
  try {
    const response = await fetch(chrome.runtime.getURL("data/darklist.json"));
    const data = await response.json();

    data.forEach((entry) => {
      const addr = entry.address.toLowerCase();
      DARKLIST.add(addr);
      DARKLIST_INFO.set(addr, {
        comment: entry.comment || "Known malicious address",
        date: entry.date || "Unknown",
      });
    });

    console.log(`[W3RG] Darklist loaded: ${DARKLIST.size} addresses`);
  } catch (e) {
    console.error("[W3RG] Failed to load darklist:", e);
  }
}

/**
 * Check if an address is blacklisted
 * @param {string} address - Ethereum address to check
 * @returns {{isBlacklisted: boolean, info: object|null}}
 */
function checkDarklist(address) {
  if (!address || typeof address !== "string") {
    return { isBlacklisted: false, info: null };
  }

  const normalized = address.toLowerCase();

  if (DARKLIST.has(normalized)) {
    return {
      isBlacklisted: true,
      info: DARKLIST_INFO.get(normalized) || {
        comment: "Known malicious address",
      },
    };
  }

  return { isBlacklisted: false, info: null };
}

/**
 * Get darklist score contribution
 * @param {string} address - Address to check
 * @returns {number} Score from 0-100 (0 if not in list, 100 if blacklisted)
 */
function getDarklistScore(address) {
  const { isBlacklisted } = checkDarklist(address);
  return isBlacklisted ? 100 : 0;
}

// Initialize on load
loadDarklist();

// Export for use in background.js
if (typeof module !== "undefined") {
  module.exports = { checkDarklist, getDarklistScore, loadDarklist };
}
