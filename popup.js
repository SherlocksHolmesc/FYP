async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function level(score) {
  if (score >= 80) return { text: "CRITICAL", color: "#dc3545" };
  if (score >= 60) return { text: "HIGH", color: "#fd7e14" };
  if (score >= 30) return { text: "MEDIUM", color: "#ffc107" };
  return { text: "LOW", color: "#28a745" };
}

function renderScoreBar(label, value, max = 100) {
  const pct = Math.min(100, Math.round((value / max) * 100));
  return `
    <div class="score-component">
      <span class="score-label">${label}</span>
      <div class="score-bar-container">
        <div class="score-bar" style="width: ${pct}%; background: ${
    value > 60 ? "#dc3545" : value > 30 ? "#ffc107" : "#28a745"
  }"></div>
      </div>
      <span class="score-value">${value}</span>
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
    el.innerHTML = `<div class="muted">No wallet activity detected on this tab yet.</div>`;
    return;
  }

  const score = data.analysis?.score ?? 0;
  const reasons = data.analysis?.reasons ?? [];
  const components = data.analysis?.components || {
    heuristic: score,
    darklist: 0,
    ml: score,
  };
  const mlPrediction = data.analysis?.mlPrediction || "N/A";
  const lvl = level(score);

  el.innerHTML = `
    <div class="score" style="color: ${
      lvl.color
    }">${score} <span class="muted">/100</span></div>
    <div class="level" style="background: ${lvl.color}">${lvl.text}</div>
    ${
      mlPrediction !== "N/A"
        ? `<div class="prediction">${mlPrediction}</div>`
        : ""
    }
    <div class="muted url">${data.href}</div>
    
    <hr/>
    
    <div class="section-title">Hybrid Score Breakdown</div>
    ${renderScoreBar("Heuristic", components.heuristic)}
    ${renderScoreBar("Darklist", components.darklist)}
    ${renderScoreBar("ML + GoPlus", components.ml)}
    
    <hr/>
    
    <div class="muted">Method: <b>${data.method}</b></div>
    
    <div class="section-title">Risk Factors</div>
    <ul class="reasons">${reasons.map((r) => `<li>${r}</li>`).join("")}</ul>
  `;
})();
