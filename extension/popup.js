async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function getRiskLevel(score) {
  if (score >= 80) return { text: "CRITICAL", class: "critical" };
  if (score >= 60) return { text: "HIGH RISK", class: "high" };
  if (score >= 30) return { text: "MEDIUM", class: "medium" };
  return { text: "LOW RISK", class: "low" };
}

function getProgressColor(value) {
  if (value >= 70) return "#ef4444";
  if (value >= 40) return "#f59e0b";
  return "#22c55e";
}

function renderComponent(label, value, num) {
  return `
    <div class="component">
      <span class="component-label">${label}</span>
      <div class="progress-bar">
        <div class="progress-fill" style="width: ${value}%; background: ${getProgressColor(
    value
  )}"></div>
      </div>
      <span class="component-value">${value}</span>
    </div>
  `;
}

function renderMarquee() {
  return `
    <div class="marquee">
      <div class="marquee-track">
        ${[1, 2, 3]
          .map(
            () => `
          <div class="marquee-content">
            <span>BLOCKCHAIN SECURITY</span>
            <span class="marquee-dot">◆</span>
            <span>ML DETECTION</span>
            <span class="marquee-dot">◆</span>
            <span>REAL-TIME</span>
            <span class="marquee-dot">◆</span>
            <span>GUARDCHAIN</span>
            <span class="marquee-dot">◆</span>
          </div>
        `
          )
          .join("")}
      </div>
    </div>
  `;
}

(async () => {
  const tab = await getActiveTab();

  console.log(`[W3RG POPUP] Querying data for tab ${tab.id}: ${tab.url}`);

  const data = await chrome.runtime.sendMessage({
    type: "GET_LATEST",
    tabId: tab.id,
  });

  console.log(`[W3RG POPUP] Received data:`, data);

  const el = document.getElementById("app");

  if (!data) {
    el.innerHTML = `
      <div class="header">
        <div class="logo">
          <span class="section-num">00</span>
          <span class="logo-text">GuardChain</span>
        </div>
        <div class="status-pill">
          <span class="status-dot"></span>
          <span>Active</span>
        </div>
      </div>

      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        <div class="empty-title">No Activity</div>
        <div class="empty-text">
          Navigate to a dApp and interact with it to see real-time risk analysis
        </div>
      </div>

      ${renderMarquee()}
    `;
    return;
  }

  const score = data.analysis?.score ?? 0;
  const reasons = data.analysis?.reasons ?? [];
  const components = data.analysis?.components || {
    heuristic: score,
    darklist: 0,
    ml: score,
  };
  const simulation = data.analysis?.simulation || null;
  const blocked = data.analysis?.blocked || false;
  const lvl = getRiskLevel(score);
  const hostname = new URL(data.href).hostname;
  const method = data.method || "Unknown";
  const params = data.params || [];
  const origin = data.origin || hostname;

  el.innerHTML = `
    <div class="header">
      <div class="logo">
        <span class="section-num">00</span>
        <span class="logo-text">GuardChain</span>
      </div>
      <div class="status-pill">
        <span class="status-dot"></span>
        <span>Active</span>
      </div>
    </div>

    <div class="url-bar">
      <span class="url-icon">🔗</span>
      <span class="url-text">${hostname}</span>
    </div>

    <div class="score-section">
      <div class="score-label">Risk Score</div>
      <div class="score-value ${lvl.class}">${score}</div>
      <div class="risk-badge ${lvl.class}">
        <span>${lvl.text}</span>
      </div>
      ${blocked ? '<div class="blocked-badge">🚨 BLOCKED</div>' : ""}
    </div>

    ${
      simulation
        ? `
      <div class="info-card">
        <div class="card-header">
          <span class="card-title">dApp Simulation</span>
          <span class="card-num">01</span>
        </div>
        <div class="info-row">
          <span class="info-label">Status</span>
          <span class="info-value ${
            simulation.is_malicious ? "text-danger" : "text-safe"
          }">
            ${simulation.is_malicious ? "⚠️ MALICIOUS" : "✓ SAFE"}
          </span>
        </div>
        <div class="info-row">
          <span class="info-label">Confidence</span>
          <span class="info-value">${simulation.confidence}%</span>
        </div>
        ${
          simulation.method
            ? `
          <div class="info-row">
            <span class="info-label">Detection Method</span>
            <span class="info-value" style="font-size: 11px; opacity: 0.9;">${simulation.method}</span>
          </div>
        `
            : ""
        }
        ${
          simulation.reason
            ? `
          <div class="info-row">
            <span class="info-label">Analysis</span>
            <span class="info-value" style="font-size: 11px; opacity: 0.9;">${simulation.reason}</span>
          </div>
        `
            : ""
        }
        ${
          simulation.typosquatting_detected
            ? `
          <div class="info-row">
            <span class="info-label">⚠️ Typosquatting</span>
            <span class="info-value text-danger">Did you mean ${simulation.similar_to}?</span>
          </div>
        `
            : ""
        }
        ${
          simulation.risk_factors && simulation.risk_factors.length > 0
            ? `
          <div class="info-row" style="flex-direction: column; align-items: flex-start;">
            <span class="info-label">Risk Factors</span>
            <div style="margin-top: 6px; width: 100%;">
              ${simulation.risk_factors
                .slice(0, 3)
                .map(
                  (f) => `
                <div style="padding: 4px 8px; background: rgba(239, 68, 68, 0.1); border-left: 2px solid #ef4444; margin-bottom: 4px; font-size: 11px; border-radius: 3px;">
                  ${
                    typeof f === "string"
                      ? f
                      : f.description || f.name || JSON.stringify(f)
                  }
                </div>
              `
                )
                .join("")}
              ${
                simulation.risk_factors.length > 3
                  ? `
                <div style="font-size: 10px; opacity: 0.6; margin-top: 4px;">
                  +${simulation.risk_factors.length - 3} more
                </div>
              `
                  : ""
              }
            </div>
          </div>
        `
            : ""
        }
      </div>
    `
        : ""
    }

    <div class="info-card">
      <div class="card-header">
        <span class="card-title">Request Details</span>
        <span class="card-num">${simulation ? "02" : "01"}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Method</span>
        <span class="info-value" style="font-family: 'JetBrains Mono', monospace; font-size: 12px; background: rgba(139, 92, 246, 0.1); padding: 2px 6px; border-radius: 4px;">${method}</span>
      </div>
      ${
        params && params.length > 0
          ? `
        <div class="info-row" style="flex-direction: column; align-items: flex-start;">
          <span class="info-label">Parameters</span>
          <div style="margin-top: 6px; width: 100%; max-height: 120px; overflow-y: auto;">
            ${params
              .slice(0, 5)
              .map(
                (p, i) => `
              <div style="padding: 6px 8px; background: rgba(0, 0, 0, 0.2); margin-bottom: 4px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 10px; word-break: break-all;">
                <span style="color: #a5b4fc; font-weight: 600;">[${i}]</span>
                <span style="color: #cbd5e1; margin-left: 6px;">
                  ${
                    typeof p === "string" && p.length > 50
                      ? p.substring(0, 50) + "..."
                      : JSON.stringify(p)
                  }
                </span>
              </div>
            `
              )
              .join("")}
            ${
              params.length > 5
                ? `
              <div style="font-size: 10px; opacity: 0.6; padding: 4px 8px;">
                +${params.length - 5} more parameters
              </div>
            `
                : ""
            }
          </div>
        </div>
      `
          : ""
      }
      <div class="info-row">
        <span class="info-label">Origin</span>
        <span class="info-value" style="font-size: 11px; word-break: break-all;">${origin}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Timestamp</span>
        <span class="info-value">${new Date(
          data.ts
        ).toLocaleTimeString()}</span>
      </div>
    </div>

    ${
      reasons.length > 0
        ? `
      <div class="info-card">
        <div class="card-header">
          <span class="card-title">Risk Indicators</span>
          <span class="card-num">${simulation ? "03" : "02"}</span>
        </div>
        <div class="flags-list">
          ${reasons
            .map(
              (r, i) => `
            <div class="flag-item">
              <span class="flag-icon">!</span>
              <span>${r}</span>
            </div>
          `
            )
            .join("")}
        </div>
      </div>
    `
        : ""
    }

    ${renderMarquee()}
  `;
})();
