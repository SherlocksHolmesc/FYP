const latestByTab = new Map();

// ============================================================
// DARKLIST MODULE - Known malicious addresses
// ============================================================
let DARKLIST = new Set();
let DARKLIST_INFO = new Map();
let darklistLoaded = false;

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

    darklistLoaded = true;
    console.log(`[W3RG] Darklist loaded: ${DARKLIST.size} addresses`);
  } catch (e) {
    console.error("[W3RG] Failed to load darklist:", e);
  }
}

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

// Load darklist on startup
loadDarklist();

// ============================================================
// SCORING WEIGHTS (Hybrid Model)
// ============================================================
const WEIGHTS = {
  heuristic: 0.35, // Rule-based detection
  darklist: 0.3, // Known bad addresses
  ml: 0.35, // ML model from backend API
};

// ML API Configuration
const ML_API_URL = "http://localhost:5000";
const ML_API_TIMEOUT = 8000; // 8 seconds timeout

// Cache for ML scores (avoid repeated API calls)
const mlScoreCache = new Map();
const ML_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Cache for simulation results (dApp behavior analysis)
const simulationCache = new Map();
const SIM_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// ============================================================
// ML API FUNCTIONS
// ============================================================

async function getMLScore(address) {
  if (!address) return { score: 0, error: "No address provided" };

  const normalized = address.toLowerCase();

  // Check cache first
  const cached = mlScoreCache.get(normalized);
  if (cached && Date.now() - cached.timestamp < ML_CACHE_TTL) {
    console.log(`[W3RG] ML score from cache: ${cached.score}`);
    return cached;
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), ML_API_TIMEOUT);

    const response = await fetch(`${ML_API_URL}/score/${address}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    const data = await response.json();

    const result = {
      score: data.score || 0,
      prediction: data.prediction || "UNKNOWN",
      confidence: data.confidence || 0,
      goplusFlags: data.goplus_flags || [],
      isHoneypot: data.is_honeypot || false,
      mlScore: data.components?.ml_score || 0,
      goplusScore: data.components?.goplus_score || 0,
      timestamp: Date.now(),
    };

    // Cache the result
    mlScoreCache.set(normalized, result);
    console.log(
      `[W3RG] ML score from API: ${result.score} (${result.prediction})`
    );

    return result;
  } catch (e) {
    console.warn(`[W3RG] ML API error: ${e.message}`);
    return { score: 0, error: e.message, fallback: true };
  }
}

// ============================================================
// SIMULATION API FUNCTIONS (Proactive dApp Analysis)
// ============================================================

async function checkSimulation(url) {
  if (!url)
    return { is_malicious: false, confidence: 0, error: "No URL provided" };

  try {
    const normalized = new URL(url).origin;

    console.log(`[W3RG] 🔍 Checking simulation for: ${normalized}`);

    // Check cache first
    const cached = simulationCache.get(normalized);
    if (cached && Date.now() - cached.timestamp < SIM_CACHE_TTL) {
      console.log(`[W3RG] Simulation from cache: ${normalized}`);
      return cached;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 90000); // 90s timeout for simulation (complex dApps like MetaMask take time)

    console.log(
      `[W3RG] 📡 Calling simulation API: ${ML_API_URL}/simulate-dapp?url=${normalized}`
    );

    const response = await fetch(
      `${ML_API_URL}/simulate-dapp?url=${encodeURIComponent(url)}`,
      { signal: controller.signal }
    );
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Simulation API returned ${response.status}`);
    }

    const data = await response.json();

    console.log(`[W3RG] 📊 Simulation response:`, data);

    const result = {
      is_malicious: data.is_malicious || false,
      confidence: data.confidence || 0,
      typosquatting_detected: data.typosquatting_detected || false,
      similar_to: data.similar_to || null,
      risk_factors: data.risk_factors || [],
      timestamp: Date.now(),
    };

    // Cache the result
    simulationCache.set(normalized, result);
    console.log(
      `[W3RG] Simulation result: ${
        result.is_malicious ? "MALICIOUS" : "SAFE"
      } (${result.confidence}% confidence)`
    );

    return result;
  } catch (e) {
    console.warn(`[W3RG] Simulation API error: ${e.message}`);

    // If timeout, assume safe with note (complex sites take long to analyze)
    if (e.message.includes("aborted")) {
      return {
        is_malicious: false,
        confidence: 70,
        error: "Analysis timeout - site may be complex",
        note: "Simulation took too long. Complex sites like wallets are harder to analyze.",
        fallback: true,
      };
    }

    return {
      is_malicious: false,
      confidence: 0,
      error: e.message,
      fallback: true,
    };
  }
}

function showDangerNotification(simResult, url) {
  const domain = new URL(url).hostname;
  let message = `This website appears to be malicious (${simResult.confidence}% confidence).`;

  if (simResult.typosquatting_detected && simResult.similar_to) {
    message += `\n\n⚠️ Typosquatting detected!\nDid you mean: ${simResult.similar_to}?`;
  }

  if (simResult.risk_factors && simResult.risk_factors.length > 0) {
    message += `\n\nRisk factors: ${simResult.risk_factors.join(", ")}`;
  }

  chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("icon128.png"), // Use extension icon
    title: "🚨 DANGER - Suspected Scam Detected!",
    message: message,
    priority: 2,
    requireInteraction: true, // User MUST dismiss
  });

  console.log(`[W3RG] 🚨 Danger notification shown for ${domain}`);
}

function showSafeNotification(simResult, url) {
  const domain = new URL(url).hostname;
  let message = `This website appears to be safe (${simResult.confidence}% confidence).`;

  chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("icon128.png"),
    title: "✅ Safe Website Detected",
    message: message,
    priority: 2,
    requireInteraction: true, // Changed to true - user must dismiss
  });

  console.log(`[W3RG] ✅ Safe notification shown for ${domain}`);
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

function hexToBigInt(hex) {
  if (!hex || typeof hex !== "string") return null;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

function isUnlimitedApproval(amountHex) {
  const v = hexToBigInt(amountHex);
  if (v === null) return false;
  // "Unlimited" heuristics: very close to max uint256
  const max = (1n << 256n) - 1n;
  return v > (max * 95n) / 100n; // >95% of max
}

function decodeTxData(data) {
  if (
    !data ||
    typeof data !== "string" ||
    !data.startsWith("0x") ||
    data.length < 10
  ) {
    return { fn: "unknown", details: {} };
  }
  const selector = data.slice(0, 10).toLowerCase();
  // ERC20 approve(address,uint256) => 0x095ea7b3
  if (selector === "0x095ea7b3") {
    // ABI-encoded: 4 bytes selector + 32 bytes spender + 32 bytes amount
    const spender = "0x" + data.slice(10 + 24, 10 + 64); // last 40 hex of first 32-byte word
    const amountHex = "0x" + data.slice(10 + 64, 10 + 128);
    return { fn: "approve", details: { spender, amountHex } };
  }
  // setApprovalForAll(address,bool) => 0xa22cb465
  if (selector === "0xa22cb465") {
    const operator = "0x" + data.slice(10 + 24, 10 + 64);
    const boolWord = "0x" + data.slice(10 + 64, 10 + 128);
    const enabled = hexToBigInt(boolWord) === 1n;
    return { fn: "setApprovalForAll", details: { operator, enabled } };
  }
  return { fn: "unknown", details: { selector } };
}

// ============================================================
// HEURISTIC SCORING (Rule-based detection)
// ============================================================

function getHeuristicScore(req) {
  const reasons = [];
  let score = 0;
  let spenderAddress = null;

  const method = req.method;

  // Transactions
  if (method === "eth_sendTransaction" || method === "eth_sendRawTransaction") {
    const tx = req.params?.[0] || {};
    const decoded = decodeTxData(tx.data);

    if (decoded.fn === "approve") {
      score = 80;
      reasons.push("ERC20 approval transaction requested");
      spenderAddress = decoded.details.spender;

      if (isUnlimitedApproval(decoded.details.amountHex)) {
        score = 95;
        reasons.push("⚠️ UNLIMITED token approval detected");
      }
    } else if (decoded.fn === "setApprovalForAll") {
      spenderAddress = decoded.details.operator;

      if (decoded.details.enabled) {
        score = 95;
        reasons.push("⚠️ NFT setApprovalForAll(true) detected");
      } else {
        score = 20;
        reasons.push("NFT approval revoked (setApprovalForAll(false))");
      }
    } else {
      score = 30;
      reasons.push("Transaction requested (unknown contract call)");
    }

    return { score, reasons, decoded, spenderAddress };
  }

  // Typed data signatures (Permit-ish)
  if (method === "eth_signTypedData_v4") {
    score = 70;
    reasons.push("Typed-data signature requested (eth_signTypedData_v4)");

    const typedStr = req.params?.[1];
    if (typeof typedStr === "string") {
      const lower = typedStr.toLowerCase();

      // Try to extract spender from typed data
      try {
        const parsed = JSON.parse(typedStr);
        spenderAddress = parsed?.message?.spender || null;
      } catch {}

      if (
        lower.includes("permit2") ||
        lower.includes("permit") ||
        lower.includes("spender") ||
        lower.includes("value")
      ) {
        score = 85;
        reasons.push("⚠️ Typed-data resembles permit/approval intent");
      }
    }
    return { score, reasons, decoded: { fn: "typedData" }, spenderAddress };
  }

  // Raw signatures
  if (method === "personal_sign" || method === "eth_sign") {
    score = 40;
    reasons.push(`${method} signature requested`);
    const payload = req.params?.join(" ").toLowerCase?.() || "";
    if (
      payload.includes("permit") ||
      payload.includes("approve") ||
      payload.includes("spender")
    ) {
      score = 70;
      reasons.push("Signature text contains approval-like keywords");
    }
    return { score, reasons, decoded: { fn: "rawSign" }, spenderAddress };
  }

  // Wallet connect & others
  if (method === "eth_requestAccounts") {
    return {
      score: 10,
      reasons: ["Wallet connection requested"],
      decoded: { fn: "connect" },
      spenderAddress,
    };
  }

  return {
    score: 15,
    reasons: ["Wallet RPC method requested"],
    decoded: { fn: "other", method },
    spenderAddress,
  };
}

// ============================================================
// HYBRID SCORING SYSTEM
// ============================================================

async function scoreRequest(req) {
  // Step 1: Get heuristic score
  const heuristic = getHeuristicScore(req);

  // Step 2: Check darklist for spender address
  let darklistScore = 0;
  let darklistInfo = null;

  if (heuristic.spenderAddress) {
    const darklistCheck = checkDarklist(heuristic.spenderAddress);
    if (darklistCheck.isBlacklisted) {
      darklistScore = 100;
      darklistInfo = darklistCheck.info;
      heuristic.reasons.push(`🚨 BLACKLISTED ADDRESS: ${darklistInfo.comment}`);
    }
  }

  // Step 3: Get ML score from backend API
  let mlScore = heuristic.score; // Default fallback
  let mlResult = null;

  if (heuristic.spenderAddress) {
    mlResult = await getMLScore(heuristic.spenderAddress);
    if (!mlResult.error && !mlResult.fallback) {
      mlScore = mlResult.score;
      if (mlResult.prediction === "FRAUD" && mlResult.confidence > 0.7) {
        heuristic.reasons.push(
          `🤖 ML Model: ${mlResult.prediction} (${Math.round(
            mlResult.confidence * 100
          )}% confidence)`
        );
      }

      // Add GoPlus flags as warnings
      if (mlResult.goplusFlags && mlResult.goplusFlags.length > 0) {
        mlResult.goplusFlags.forEach((flag) => {
          if (!flag.startsWith("✓")) {
            // Skip positive indicators
            heuristic.reasons.push(`⚠️ GoPlus: ${flag}`);
          }
        });
      }

      // Honeypot warning
      if (mlResult.isHoneypot) {
        heuristic.reasons.push(`🚨 HONEYPOT DETECTED - Cannot sell tokens!`);
      }
    } else if (mlResult.fallback) {
      heuristic.reasons.push("ML API unavailable - using heuristic fallback");
    }
  }

  // Step 4: Calculate weighted hybrid score
  let finalScore;

  if (darklistScore > 0) {
    // If address is blacklisted, override with high score
    finalScore = Math.max(
      95,
      Math.round(
        WEIGHTS.heuristic * heuristic.score +
          WEIGHTS.darklist * darklistScore +
          WEIGHTS.ml * mlScore
      )
    );
  } else {
    // Normal weighted calculation
    finalScore = Math.round(
      WEIGHTS.heuristic * heuristic.score +
        WEIGHTS.darklist * darklistScore +
        WEIGHTS.ml * mlScore
    );
  }

  return {
    score: finalScore,
    reasons: heuristic.reasons,
    decoded: heuristic.decoded,
    components: {
      heuristic: heuristic.score,
      darklist: darklistScore,
      ml: mlScore,
    },
    mlPrediction: mlResult?.prediction || null,
    darklistInfo,
  };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "WALLET_REQUEST") {
    const tabId = sender.tab?.id;
    const url = sender.tab?.url;
    if (!tabId) return;

    // Run simulation FIRST (proactive security check)
    (async () => {
      const simResult = await checkSimulation(url);

      // If simulation detects malicious behavior, store it but don't block (user can decide)
      if (simResult.is_malicious && simResult.confidence >= 85) {
        console.log(
          `[W3RG] ⚠️ Malicious simulation detected on ${url} (${simResult.confidence}% confidence)`
        );

        // Store simulation warning info (but allow request to continue)
        const analysis = {
          score: 85,
          reasons: [
            `⚠️ Simulation detected ${simResult.confidence}% malicious confidence`,
            ...(simResult.typosquatting_detected
              ? [`Typosquatting: Site mimics ${simResult.similar_to}`]
              : []),
            ...(simResult.risk_factors || []).map((f) =>
              typeof f === "string"
                ? f
                : f.description || f.name || JSON.stringify(f)
            ),
          ],
          decoded: { fn: msg.payload.method },
          components: {
            heuristic: 0,
            darklist: 0,
            ml: 85,
          },
          simulation: simResult,
          blocked: false, // Don't block - just warn
        };

        latestByTab.set(tabId, { ...msg.payload, analysis });
      }

      // Always proceed with normal scoring (don't block)
      scoreRequest(msg.payload).then((analysis) => {
        // Attach simulation result to analysis
        analysis.simulation = simResult;
        latestByTab.set(tabId, { ...msg.payload, analysis });
        sendResponse({ blocked: false });
      });
    })();

    return true; // Keep channel open for async
  }

  if (msg?.type === "GET_LATEST") {
    const tabId = msg.tabId;
    sendResponse(latestByTab.get(tabId) || null);
    return true; // Keep channel open for async
  }

  // NEW: Proactive page load simulation (background cache warming)
  if (msg?.type === "PAGE_LOADED") {
    console.log(`[W3RG] 📄 PAGE_LOADED message received:`, msg.url);
    const url = msg.url;
    const tabId = sender.tab?.id;

    if (url && (url.startsWith("http://") || url.startsWith("https://"))) {
      // Silently check simulation in background (populates cache)
      checkSimulation(url).then((simResult) => {
        console.log(
          `[W3RG] 🔔 Deciding notification - malicious: ${simResult.is_malicious}, confidence: ${simResult.confidence}`
        );

        // CRITICAL: Store simulation result for popup to retrieve!
        if (tabId) {
          const analysis = {
            score: simResult.is_malicious ? 85 : 10,
            reasons: simResult.is_malicious
              ? [
                  `Simulation detected ${simResult.confidence}% malicious confidence`,
                  ...(simResult.typosquatting_detected
                    ? [`Typosquatting: Site mimics ${simResult.similar_to}`]
                    : []),
                  ...(simResult.risk_factors || []).map((f) =>
                    typeof f === "string"
                      ? f
                      : f.description || f.name || JSON.stringify(f)
                  ),
                ]
              : ["No threats detected"],
            components: {
              heuristic: 0,
              darklist: 0,
              ml: simResult.is_malicious ? 85 : 10,
            },
            simulation: simResult,
            blocked: false,
          };

          latestByTab.set(tabId, {
            origin: url,
            href: url,
            ts: Date.now(),
            analysis,
          });

          console.log(`[W3RG] 💾 Stored simulation data for tab ${tabId}`);
        }

        // Send result to content.js to show on-page banner
        if (tabId && simResult.confidence >= 80) {
          chrome.tabs
            .sendMessage(tabId, {
              type: "SHOW_BANNER",
              data: simResult,
            })
            .catch((err) =>
              console.log("[W3RG] Could not send banner message:", err)
            );
          console.log(`[W3RG] ✅ Banner message sent to tab ${tabId}`);
        } else {
          console.log(
            `[W3RG] No banner (confidence too low: ${simResult.confidence}%)`
          );
        }
      });
    } else {
      console.log(`[W3RG] ⏭️ Skipping non-http URL: ${url}`);
    }
  }
});
