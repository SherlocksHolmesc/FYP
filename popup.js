async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function getRiskLevel(score) {
  if (score >= 80) return { text: "CRITICAL", color: "#dc3545" };
  if (score >= 60) return { text: "HIGH", color: "#fd7e14" };
  if (score >= 30) return { text: "MEDIUM", color: "#ffc107" };
  return { text: "LOW", color: "#28a745" };
}

function getProgressColor(value) {
  if (value >= 70) return "#dc3545";
  if (value >= 40) return "#ffc107";
  return "#27ae60";
}

function renderComponent(label, value) {
  return `
    <div class="component">
      <span class="component-label">${label}</span>
      <div class="progress-bar">
        <div class="progress-fill" style="width: ${value}%; background: ${getProgressColor(value)}"></div>
      </div>
      <span class="component-value">${value}</span>
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
      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        <div class="empty-title">No Activity Detected</div>
        <div class="empty-text">
          Browse a dApp and interact with it to see risk analysis
        </div>
      </div>
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
        <span class="shield-icon">🛡️</span>
        <span>Risk Guard</span>
      </div>
      <div class="status-badge">ACTIVE</div>
    </div>

    <div class="url-badge">
      <span class="pulse"></span>
      <span class="url-text">${hostname}</span>
    </div>

    <div class="score-card">
      <div class="score-content">
        <div class="score-value" style="color: ${lvl.color}">${score}</div>
        <div class="score-label">Risk Score</div>
        <div class="risk-badge" style="background: ${lvl.color}">${lvl.text}</div>
      </div>
    </div>

    <div class="info-card">
      <div class="info-row">
        <span class="info-label">Request Type</span>
        <span class="info-value">${data.method || 'Unknown'}</span>
      </div>
    </div>

    ${components.heuristic !== undefined || components.darklist !== undefined || components.ml !== undefined ? `
      <div class="info-card">
        <div class="components-title">Detection Breakdown</div>
        ${components.heuristic !== undefined ? renderComponent('Heuristic', components.heuristic) : ''}
        ${components.darklist !== undefined ? renderComponent('Blacklist', components.darklist) : ''}
        ${components.ml !== undefined ? renderComponent('ML Model', components.ml) : ''}
      </div>
    ` : ''}

    ${reasons.length > 0 ? `
      <div class="info-card flags-section">
        <div class="components-title">Risk Indicators</div>
        <div class="flags-list">
          ${reasons.map(r => `<div class="flag-item">${r}</div>`).join('')}
        </div>
      </div>
    ` : ''}
  `;
})();
