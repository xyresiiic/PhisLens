/* ============================================================
   PhishLens -- Frontend
   ============================================================ */

const emailInput = document.getElementById('email-input');
const analyzeBtn = document.getElementById('analyze-btn');
const errorBox   = document.getElementById('error-box');
const results    = document.getElementById('results');

const SAMPLE_FILES = {
  legitimate: '/samples/legitimate.eml',
  suspicious: '/samples/suspicious.eml',
  phishing:   '/samples/phishing.eml',
};

/* -- Sample loaders ----------------------------------------- */
document.querySelectorAll('.sample-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const key = btn.dataset.sample;
    const res  = await fetch(SAMPLE_FILES[key]);
    const text = await res.text();
    emailInput.value = text;
    analyzeBtn.disabled = false;
    hideResults();
    hideError();
  });
});

/* -- Main analyze flow -------------------------------------- */
analyzeBtn.addEventListener('click', analyze);

async function analyze() {
  const raw = emailInput.value;
  if (!raw.trim()) return;
  setLoading(true);
  hideError();
  try {
    const res  = await fetch('/api/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ raw }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Analysis failed');
    renderResults(data);
  } catch (err) {
    showError(err.message);
    hideResults();
  } finally {
    setLoading(false);
  }
}

/* -- State helpers ------------------------------------------ */
function setLoading(loading) {
  analyzeBtn.disabled    = loading || !emailInput.value.trim();
  analyzeBtn.textContent = loading ? 'Analyzing\u2026' : 'Analyze email';
}
function showError(msg) {
  errorBox.textContent = msg;
  errorBox.classList.remove('hidden');
}
function hideError()   { errorBox.classList.add('hidden'); }
function hideResults() { results.classList.add('hidden'); }

/* -- Risk tier helpers -------------------------------------- */
function scoreToTier(score, classification) {
  if (classification === 'LOW RISK')   return { key: 'low',      label: 'Low Risk' };
  if (classification === 'SUSPICIOUS') return { key: 'medium',   label: 'Suspicious' };
  if (score >= 80)                     return { key: 'critical',  label: 'Critical' };
  return                                      { key: 'high',      label: 'High Risk' };
}
function sevClass(sev) {
  if (sev === 'high')   return 'sev-high';
  if (sev === 'medium') return 'sev-medium';
  return 'sev-low';
}

/* -- Main renderer ------------------------------------------ */
function renderResults(result) {
  results.classList.remove('hidden');
  renderGauge(result);
  renderSignalCards(result.evidence, result.score);
  renderSender(result.sender);
  renderAuth(result.auth);
  renderUrls(result.urls);
  renderRecommendation(result.recommendation);
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* -- Risk gauge --------------------------------------------- */
function renderGauge(result) {
  const el   = document.getElementById('risk-gauge');
  const tier = scoreToTier(result.score, result.classification);
  const pct  = Math.min(result.score, 100);
  el.innerHTML = `
    <div class="risk-gauge-panel tier-${tier.key}" role="region" aria-label="Risk score">
      <div class="gauge-top">
        <div class="gauge-meta">
          <p class="gauge-meta-label">Subject</p>
          <p class="gauge-subject" title="${escapeHtml(result.subject)}">${escapeHtml(result.subject)}</p>
        </div>
        <div class="gauge-score-block">
          <div class="gauge-tier-wrap">
            <span class="gauge-tier-label-sm">Classification</span>
            <span class="gauge-tier">${escapeHtml(tier.label)}</span>
          </div>
          <div class="gauge-score-wrap">
            <span class="gauge-score-label">Risk Score</span>
            <span class="gauge-score" aria-label="${result.score} out of 100">${result.score}</span>
          </div>
        </div>
      </div>
      <div class="gauge-bar-track" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100">
        <div class="gauge-bar-fill" style="width:${pct}%"></div>
      </div>
      <div class="gauge-bar-labels" aria-hidden="true">
        <span class="gauge-bar-label">0 &mdash; Safe</span>
        <span class="gauge-bar-label">30</span>
        <span class="gauge-bar-label">60</span>
        <span class="gauge-bar-label">100 &mdash; Critical</span>
      </div>
    </div>
  `;
}

/* -- Signal cards ------------------------------------------- */
function renderSignalCards(evidence, totalScore) {
  const section = document.getElementById('signals-section');
  if (!evidence || evidence.length === 0) {
    section.innerHTML = `
      <div class="signals-header">
        <p class="signals-heading">Detection signals</p>
        <span class="signals-count">0 signals</span>
      </div>
      <div class="signals-grid">
        <div class="signals-empty">No indicators found. This email shows no signals from the current detector set.</div>
      </div>
    `;
    return;
  }
  const maxScore = Math.max(...evidence.map((e) => e.score), 1);
  const cards = evidence.map((item, i) => {
    const sc       = sevClass(item.severity);
    const pct      = Math.round((item.score / maxScore) * 100);
    const cardId   = `signal-card-${i}`;
    const detailId = `signal-detail-${i}`;
    return `
      <div class="signal-card ${sc}" id="${cardId}">
        <div class="signal-summary"
             role="button"
             tabindex="0"
             aria-expanded="false"
             aria-controls="${detailId}"
             onclick="toggleSignal('${cardId}')"
             onkeydown="handleSignalKey(event,'${cardId}')">
          <div class="signal-left">
            <p class="signal-name">${escapeHtml(item.indicator)}</p>
            <p class="signal-reason">${escapeHtml(item.detail || item.indicator)}</p>
          </div>
          <div class="signal-right">
            <div class="signal-weight">
              <span class="signal-weight-label">Weight</span>
              <span class="signal-weight-val ${sc}">+${item.score}</span>
            </div>
            <div class="signal-contrib-bar">
              <div class="signal-contrib-fill" style="width:${pct}%"></div>
            </div>
            <div class="signal-toggle" aria-hidden="true">
              <svg viewBox="0 0 10 10"><polyline points="2,3 5,7 8,3"/></svg>
            </div>
          </div>
        </div>
        <div class="signal-detail" id="${detailId}" aria-hidden="true">
          <div class="signal-detail-inner">
            <span class="signal-detail-label">Technical detail</span>
            <p class="signal-detail-value">${escapeHtml(item.detail || 'No additional detail available.')}</p>
            <span class="signal-detail-label">Severity &amp; contribution</span>
            <p class="signal-detail-value">${escapeHtml(item.severity)} &mdash; +${item.score} pts to total score</p>
          </div>
        </div>
      </div>
    `;
  }).join('');
  section.innerHTML = `
    <div class="signals-header">
      <p class="signals-heading">Detection signals</p>
      <span class="signals-count">${evidence.length} signal${evidence.length !== 1 ? 's' : ''} detected</span>
    </div>
    <div class="signals-grid">${cards}</div>
  `;
}

function toggleSignal(cardId) {
  const card     = document.getElementById(cardId);
  const summary  = card.querySelector('.signal-summary');
  const detail   = card.querySelector('.signal-detail');
  const expanded = card.classList.toggle('expanded');
  summary.setAttribute('aria-expanded', String(expanded));
  detail.setAttribute('aria-hidden',    String(!expanded));
}

function handleSignalKey(event, cardId) {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    toggleSignal(cardId);
  }
}

/* -- Sender panel ------------------------------------------- */
function renderSender(sender) {
  document.getElementById('sender-panel').innerHTML = `
    <div class="panel-header"><span class="panel-label">Sender analysis</span></div>
    <div class="panel-inner">
      ${infoRow('From',        sender.from)}
      ${infoRow('Reply-To',    sender.replyTo,    sender.replyToMismatch)}
      ${infoRow('Return-Path', sender.returnPath, sender.returnPathMismatch)}
    </div>
  `;
}

/* -- Auth panel --------------------------------------------- */
function renderAuth(auth) {
  document.getElementById('auth-panel').innerHTML = `
    <div class="panel-header"><span class="panel-label">Authentication</span></div>
    <div class="panel-inner">
      ${authRow('SPF',   auth.spf)}
      ${authRow('DKIM',  auth.dkim)}
      ${authRow('DMARC', auth.dmarc)}
    </div>
  `;
}

/* -- URL panel ---------------------------------------------- */
function renderUrls(urls) {
  const el = document.getElementById('url-panel');
  const flagHtml = (flags) => flags.length
    ? '<div class="url-flags">' + flags.map((f) => '<span class="url-flag">' + escapeHtml(f.label) + '</span>').join('') + '</div>'
    : '';
  const body = urls.length === 0
    ? '<p class="no-urls">No URLs found in this email.</p>'
    : urls.map((u) => `
        <div class="url-item">
          <p class="url-link">${escapeHtml(u.url)}</p>
          <p class="url-domain">${escapeHtml(u.domain)}</p>
          ${flagHtml(u.flags)}
        </div>
      `).join('');
  el.innerHTML = `
    <div class="panel-header"><span class="panel-label">URL analysis (${urls.length})</span></div>
    ${body}
  `;
}

/* -- Recommendation ----------------------------------------- */
function renderRecommendation(text) {
  document.getElementById('recommendation').innerHTML = `
    <span class="recommendation-label">Recommendation</span>
    <p class="recommendation-text">${escapeHtml(text)}</p>
  `;
}

/* -- Row helpers -------------------------------------------- */
function infoRow(label, value, flagged) {
  return `
    <div class="info-row">
      <span class="info-label">${label}</span>
      <span class="info-value ${flagged ? 'flagged' : ''}">${escapeHtml(value || '\u2014')}</span>
    </div>
  `;
}
function authRow(label, value) {
  const cls = value === 'PASS' ? 'pass' : value === 'FAIL' ? 'fail' : 'na';
  return `
    <div class="info-row">
      <span class="info-label">${label}</span>
      <span class="info-value ${cls}">${escapeHtml(value)}</span>
    </div>
  `;
}

/* -- Escape util -------------------------------------------- */
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}

/* -- Input state -------------------------------------------- */
analyzeBtn.disabled = true;
emailInput.addEventListener('input', () => {
  analyzeBtn.disabled = !emailInput.value.trim();
});
