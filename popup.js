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
  const data = await chrome.runtime.sendMessage({
    type: "GET_LATEST",
    tabId: tab.id,
  });

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
  const lvl = getRiskLevel(score);
  const hostname = new URL(data.href).hostname;

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
    </div>

    <div class="info-card">
      <div class="card-header">
        <span class="card-title">Request Info</span>
        <span class="card-num">01</span>
      </div>
      <div class="info-row">
        <span class="info-label">Method</span>
        <span class="info-value">${data.method || "Unknown"}</span>
      </div>
    </div>

    ${
      components.heuristic !== undefined ||
      components.darklist !== undefined ||
      components.ml !== undefined
        ? `
      <div class="info-card">
        <div class="card-header">
          <span class="card-title">Detection Breakdown</span>
          <span class="card-num">02</span>
        </div>
        ${
          components.heuristic !== undefined
            ? renderComponent("Heuristic", components.heuristic, "01")
            : ""
        }
        ${
          components.darklist !== undefined
            ? renderComponent("Blacklist", components.darklist, "02")
            : ""
        }
        ${
          components.ml !== undefined
            ? renderComponent("ML Model", components.ml, "03")
            : ""
        }
      </div>
    `
        : ""
    }

    ${
      reasons.length > 0
        ? `
      <div class="info-card">
        <div class="card-header">
          <span class="card-title">Risk Indicators</span>
          <span class="card-num">03</span>
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
