const emailInput = document.getElementById("email-input");
const analyzeBtn = document.getElementById("analyze-btn");
const errorBox = document.getElementById("error-box");
const results = document.getElementById("results");

const SAMPLE_FILES = {
  legitimate: "/samples/legitimate.eml",
  suspicious: "/samples/suspicious.eml",
  phishing: "/samples/phishing.eml",
};

document.querySelectorAll(".sample-btn").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const key = btn.dataset.sample;
    const res = await fetch(SAMPLE_FILES[key]);
    const text = await res.text();
    emailInput.value = text;
    hideResults();
    hideError();
  });
});

analyzeBtn.addEventListener("click", analyze);

async function analyze() {
  const raw = emailInput.value;
  if (!raw.trim()) return;

  setLoading(true);
  hideError();

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Analysis failed");
    renderResults(data);
  } catch (err) {
    showError(err.message);
    hideResults();
  } finally {
    setLoading(false);
  }
}

function setLoading(loading) {
  analyzeBtn.disabled = loading || !emailInput.value.trim();
  analyzeBtn.textContent = loading ? "Analyzing…" : "Analyze email";
}

function showError(msg) {
  errorBox.textContent = msg;
  errorBox.classList.remove("hidden");
}

function hideError() {
  errorBox.classList.add("hidden");
}

function hideResults() {
  results.classList.add("hidden");
}

function classToKey(classification) {
  if (classification === "LOW RISK") return "low";
  if (classification === "SUSPICIOUS") return "suspicious";
  return "phishing";
}

function renderResults(result) {
  results.classList.remove("hidden");
  renderRiskSummary(result);
  renderEvidence(result.evidence);
  renderSender(result.sender);
  renderAuth(result.auth);
  renderUrls(result.urls);
  renderRecommendation(result.recommendation);
}

function renderRiskSummary(result) {
  const key = classToKey(result.classification);
  const el = document.getElementById("risk-summary");
  el.className = `risk-summary ${key}`;
  el.innerHTML = `
    <div class="risk-summary-row">
      <div>
        <p class="rs-label">SUBJECT</p>
        <p class="rs-subject">${escapeHtml(result.subject)}</p>
      </div>
      <div class="risk-summary-group">
        <div>
          <p class="rs-label">RISK SCORE</p>
          <p class="rs-score">${result.score}</p>
        </div>
        <div>
          <p class="rs-label">CLASSIFICATION</p>
          <p class="rs-class">${result.classification}</p>
        </div>
      </div>
    </div>
  `;
}

function renderEvidence(evidence) {
  const el = document.getElementById("evidence-log");
  let body;
  if (evidence.length === 0) {
    body = `<p class="evidence-empty">No indicators were found. This email shows no signals from the current detector set.</p>`;
  } else {
    body = evidence
      .map(
        (item, i) => `
      <div class="evidence-item">
        <span class="evidence-index mono">${String(i + 1).padStart(2, "0")}</span>
        <div class="evidence-body">
          <div class="evidence-top">
            <p class="evidence-indicator ${item.severity}">${escapeHtml(item.indicator)}</p>
            <span class="evidence-score">+${item.score}</span>
          </div>
          ${item.detail ? `<p class="evidence-detail">${escapeHtml(item.detail)}</p>` : ""}
        </div>
      </div>
    `
      )
      .join("");
  }
  el.innerHTML = `
    <div class="panel-header"><span class="panel-label">02 — Evidence log</span></div>
    ${body}
  `;
}

function renderSender(sender) {
  const el = document.getElementById("sender-panel");
  el.innerHTML = `
    <div class="panel-header"><span class="panel-label">Sender analysis</span></div>
    <div class="panel-inner">
      ${infoRow("FROM", sender.from)}
      ${infoRow("REPLY-TO", sender.replyTo, sender.replyToMismatch)}
      ${infoRow("RETURN-PATH", sender.returnPath, sender.returnPathMismatch)}
    </div>
  `;
}

function renderAuth(auth) {
  const el = document.getElementById("auth-panel");
  el.innerHTML = `
    <div class="panel-header"><span class="panel-label">Authentication</span></div>
    <div class="panel-inner">
      ${authRow("SPF", auth.spf)}
      ${authRow("DKIM", auth.dkim)}
      ${authRow("DMARC", auth.dmarc)}
    </div>
  `;
}

function renderUrls(urls) {
  const el = document.getElementById("url-panel");
  let body;
  if (urls.length === 0) {
    body = `<p class="no-urls">No URLs found in this email.</p>`;
  } else {
    body = urls
      .map(
        (u) => `
      <div class="url-item">
        <p class="url-link mono">${escapeHtml(u.url)}</p>
        <p class="url-domain mono">${escapeHtml(u.domain)}</p>
        ${
          u.flags.length
            ? `<div class="url-flags">${u.flags
                .map((f) => `<span class="url-flag">${escapeHtml(f.label)}</span>`)
                .join("")}</div>`
            : ""
        }
      </div>
    `
      )
      .join("");
  }
  el.innerHTML = `
    <div class="panel-header"><span class="panel-label">URL analysis (${urls.length})</span></div>
    ${body}
  `;
}

function renderRecommendation(text) {
  const el = document.getElementById("recommendation");
  el.innerHTML = `
    <span class="recommendation-label">Recommendation</span>
    <p class="recommendation-text">${escapeHtml(text)}</p>
  `;
}

function infoRow(label, value, flagged) {
  return `
    <div class="info-row">
      <span class="info-label mono">${label}</span>
      <span class="info-value mono ${flagged ? "flagged" : ""}">${escapeHtml(value || "—")}</span>
    </div>
  `;
}

function authRow(label, value) {
  const statusClass = value === "PASS" ? "pass" : value === "FAIL" ? "fail" : "na";
  return `
    <div class="info-row">
      <span class="info-label mono">${label}</span>
      <span class="info-value mono ${statusClass}">${escapeHtml(value)}</span>
    </div>
  `;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

emailInput.addEventListener("input", () => {
  analyzeBtn.disabled = !emailInput.value.trim();
});
