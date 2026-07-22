// ================================================================
// VerifyNG - Main Application Logic v1.0
// Fake Alert Scanner for Nigerian Traders & POS Agents
// ================================================================

const CONFIG = { FREE_SCANS_PER_DAY: 20 };

const state = {
  voiceEnabled: true,
  selectedBank: null,
  scanHistory: JSON.parse(localStorage.getItem('vng_history') || '[]'),
  totalChecks: parseInt(localStorage.getItem('vng_checks') || '0'),
  lastResult: null,
  deferredInstall: null,
};

// ── Nigerian Bank Patterns ──────────────────────────────────────
const BANKS = {
  gtbank:     { name:'GTBank',      senders:['gtbank','gt bank','guaranty'],    keys:['acct','bal:','ref:','ngn'] },
  access:     { name:'Access Bank', senders:['access','accessbank'],            keys:['credit','debit','balance','ref'] },
  zenith:     { name:'Zenith Bank', senders:['zenith','zenithbank'],            keys:['credit','debit','avail bal'] },
  firstbank:  { name:'FirstBank',   senders:['firstbank','first bank','fbn'],   keys:['credit','debit','available balance'] },
  uba:        { name:'UBA',         senders:['uba','united bank'],              keys:['credit','debit','balance'] },
  fidelity:   { name:'Fidelity',    senders:['fidelity'],                       keys:['credit','debit','balance'] },
  fcmb:       { name:'FCMB',        senders:['fcmb'],                           keys:['credit','debit','ref'] },
  sterling:   { name:'Sterling',    senders:['sterling'],                       keys:['credit','debit','bal'] },
  stanbic:    { name:'Stanbic IBTC',senders:['stanbic','stanbicibtc'],          keys:['credit','debit','balance'] },
  opay:       { name:'OPay',        senders:['opay'],                           keys:['received','wallet','balance'] },
  kuda:       { name:'Kuda',        senders:['kuda'],                           keys:['credit','debit','balance','ref'] },
  palmpay:    { name:'PalmPay',     senders:['palmpay','palm pay'],             keys:['received','transferred','wallet'] },
  moniepoint: { name:'Moniepoint',  senders:['moniepoint','teamapt'],           keys:['credit','debit','balance','ref'] },
  wema:       { name:'Wema/ALAT',   senders:['wema','alat'],                    keys:['credit','debit','balance'] },
};

// ── Fake Alert Signatures ───────────────────────────────────────
const FAKE_SIG = [
  { p:/\b(crédited|recieved|ammount|tranfer|payed|succesfull|creditted|debitted|transfered|recived)\b/i, w:35, t:'Spelling mistake — Nigerian banks never misspell official SMS messages' },
  { p:/08[0-9]{9}|07[0-9]{9}|09[0-9]{9}/, w:40, t:'Sender is a mobile number, not a bank shortcode' },
  { p:/click here|visit link|verify your account|http:\/\//i, w:45, t:'Contains suspicious link — real bank alerts never include these' },
  { p:/congratulations|you have won|lucky winner|prize|reward/i, w:55, t:'Contains lottery/prize language — classic scam pattern' },
  { p:/\bpin\b|\bpassword\b|\botp\b|\bsecret\b|\btoken\b/i, w:65, t:'Asks for PIN/OTP/password — real bank alerts NEVER do this' },
  { p:/flash\s?transfer|fake\s?alert|test\s?transfer/i, w:80, t:'Contains keywords from fake alert generator apps' },
  { p:/your account has been successfully credited with/i, w:20, t:'Unusual phrasing — real Nigerian banks use specific standard formats' },
];

// ── Real Alert Signatures ───────────────────────────────────────
const REAL_SIG = [
  { p:/\*{2}\d{4}|\*{3}\d{4}/, w:20, t:'Account number properly masked (**1234 format) — standard bank practice' },
  { p:/ref:\s?\w{6,}|rrn:\s?\d+|tran\s?id:\s?\w+/i, w:15, t:'Contains valid transaction reference number' },
  { p:/\d{2}-[a-z]{3}-\d{4}|\d{2}\/\d{2}\/\d{4}/i, w:15, t:'Date format matches standard Nigerian bank timestamp' },
  { p:/bal:\s?ngn|available balance|avail bal|ledger bal/i, w:12, t:'Contains proper balance notation used by real banks' },
  { p:/ngn\s?[\d,]+\.\d{2}/i, w:12, t:'Amount has 2 decimal places (₦50,000.00) — standard bank format' },
  { p:/\bcr\b|\bdr\b|credit\b|debit\b/i, w:10, t:'Uses standard Cr/Dr credit-debit notation' },
];

// ── Core Analysis Engine ────────────────────────────────────────
function analyzeText(text) {
  if (!text || text.trim().length < 10) {
    return { verdict:'uncertain', confidence:0, findings:[{ type:'yellow', text:'Text too short to analyze. Paste the full SMS message.' }] };
  }

  const lower = text.toLowerCase();
  let fakeScore = 0, realScore = 0;
  const findings = [];

  FAKE_SIG.forEach(s => { if (s.p.test(text)) { fakeScore += s.w; findings.push({ type:'red', text:s.t }); } });
  REAL_SIG.forEach(s => { if (s.p.test(text)) { realScore += s.w; findings.push({ type:'green', text:s.t }); } });

  // Bank matching
  if (state.selectedBank && BANKS[state.selectedBank]) {
    const bp = BANKS[state.selectedBank];
    const nameFound = bp.senders.some(n => lower.includes(n));
    if (!nameFound) {
      fakeScore += 30;
      findings.push({ type:'red', text:`"${bp.name}" not mentioned — doesn't match selected bank` });
    } else {
      realScore += 15;
      findings.push({ type:'green', text:`Bank name "${bp.name}" confirmed in message` });
    }
    const kw = bp.keys.filter(k => lower.includes(k));
    if (kw.length >= 2) { realScore += 12; findings.push({ type:'green', text:`Contains ${kw.length} standard ${bp.name} keywords` }); }
    else if (kw.length === 0) { fakeScore += 15; findings.push({ type:'yellow', text:`Missing standard ${bp.name} message keywords` }); }
  } else {
    let detected = null;
    for (const [, bp] of Object.entries(BANKS)) {
      if (bp.senders.some(n => lower.includes(n))) { detected = bp.name; realScore += 10; findings.push({ type:'green', text:`Auto-detected: ${bp.name} message format` }); break; }
    }
    if (!detected) findings.push({ type:'yellow', text:'No specific bank auto-detected — select bank above for better accuracy' });
  }

  if (text.length < 40) { fakeScore += 20; findings.push({ type:'yellow', text:'Very short — real bank alerts are longer and contain more detail' }); }
  if (!/[\d,]{3,}/.test(text)) { fakeScore += 25; findings.push({ type:'red', text:'No transaction amount found — all real bank alerts include an amount' }); }

  // Duplicate check
  const snippet = text.substring(0, 50);
  if (state.scanHistory.slice(0, 10).some(r => r.preview.startsWith(snippet.substring(0, 30)))) {
    fakeScore += 20;
    findings.push({ type:'red', text:'This alert was scanned recently — possible duplicate/reused receipt' });
  }

  if (!findings.length) findings.push({ type:'yellow', text:'No strong patterns found — verify directly in your banking app' });

  const total = fakeScore + realScore;
  let verdict, confidence;
  if (total === 0) { verdict = 'uncertain'; confidence = 50; }
  else if (fakeScore > realScore * 1.4) { verdict = 'fake'; confidence = Math.min(97, Math.round((fakeScore / total) * 100)); }
  else if (realScore > fakeScore) { verdict = 'real'; confidence = Math.min(92, Math.round((realScore / total) * 100)); }
  else { verdict = 'uncertain'; confidence = 45; }

  return { verdict, confidence, findings };
}

// ── Extract Amount ──────────────────────────────────────────────
function extractAmount(text) {
  const m = text.match(/(?:ngn|₦)\s?([\d,]+(?:\.\d{2})?)/i) || text.match(/([\d,]{4,}(?:\.\d{2})?)/);
  return m ? parseFloat(m[1].replace(/,/g, '')) : null;
}

// ── OCR with Tesseract ──────────────────────────────────────────
async function runOCR(imageData) {
  showScanning(true, 'Reading image text...');
  try {
    const result = await Tesseract.recognize(imageData, 'eng', {
      logger: m => { if (m.status === 'recognizing text') updateScanMsg(`Reading... ${Math.round(m.progress * 100)}%`); }
    });
    showScanning(false);
    return result.data.text;
  } catch {
    showScanning(false);
    showToast('Could not read image. Try pasting the SMS text instead.', 'warn');
    return null;
  }
}

// ── Scan Limit ─────────────────────────────────────────────────
function checkLimit() {
  const today = new Date().toDateString();
  const s = JSON.parse(localStorage.getItem('vng_daily') || '{}');
  if (s.date !== today) { localStorage.setItem('vng_daily', JSON.stringify({ date: today, count: 0 })); return true; }
  if (s.count >= CONFIG.FREE_SCANS_PER_DAY) { showUpgradePrompt(); return false; }
  return true;
}

function bumpCount() {
  const today = new Date().toDateString();
  const s = JSON.parse(localStorage.getItem('vng_daily') || '{}');
  const count = (s.date === today ? s.count : 0) + 1;
  localStorage.setItem('vng_daily', JSON.stringify({ date: today, count }));
  state.totalChecks++;
  localStorage.setItem('vng_checks', state.totalChecks);
  document.getElementById('totalChecks').textContent = state.totalChecks;
  document.getElementById('scanCountBadge').textContent = `${count}/${CONFIG.FREE_SCANS_PER_DAY} today`;
}

function showUpgradePrompt() {
  document.getElementById('upgradeModal').classList.remove('hidden');
}

// ── Image Upload Handler ────────────────────────────────────────
async function handleImageUpload(e) {
  const file = e.target.files[0];
  if (!file || !checkLimit()) return;
  const reader = new FileReader();
  reader.onload = async ev => {
    const data = ev.target.result;
    const preview = document.getElementById('imagePreview');
    const ph = document.getElementById('uploadPlaceholder');
    preview.src = data; preview.classList.remove('hidden'); ph.classList.add('hidden');
    const text = await runOCR(data);
    if (text) processResult(text);
  };
  reader.readAsDataURL(file);
  e.target.value = '';
}

// ── Manual SMS Scan ─────────────────────────────────────────────
function runScan() {
  const text = document.getElementById('alertInput').value.trim();
  if (!text) { showToast('Paste an SMS or alert text first', 'warn'); return; }
  if (!checkLimit()) return;
  document.getElementById('scanBtn').disabled = true;
  showScanning(true, 'Checking against Nigerian bank patterns...');
  setTimeout(() => {
    processResult(text);
    showScanning(false);
    document.getElementById('scanBtn').disabled = false;
  }, 1600);
}

// ── Process & Display Result ────────────────────────────────────
function processResult(text) {
  const result = analyzeText(text);
  const amount = extractAmount(text);
  showResult(result);
  bumpCount();

  // Save history
  const entry = { verdict: result.verdict, confidence: result.confidence, preview: text.substring(0, 60), time: new Date().toLocaleTimeString('en-NG', { hour: '2-digit', minute: '2-digit' }), amount, date: new Date().toDateString() };
  state.scanHistory.unshift(entry);
  if (state.scanHistory.length > 50) state.scanHistory.pop();
  localStorage.setItem('vng_history', JSON.stringify(state.scanHistory));

  // Ledger
  if (result.verdict === 'real' && amount) addLedger(amount, 'verified');
  else if (result.verdict === 'fake') addLedger(amount || 0, 'blocked');
  updateLedgerSummary();

  state.lastResult = { ...result, text };

  // Voice
  if (state.voiceEnabled) {
    if (result.verdict === 'fake') speakAlert('Warning! Fake alert suspected. Do not release goods.');
    else if (result.verdict === 'real') speakAlert(`Alert looks real. ${amount ? '₦' + amount.toLocaleString('en-NG') + ' confirmed.' : 'Verify in your banking app.'}`);
    else speakAlert('Result uncertain. Please verify in your banking app directly.');
  }
}

// ── Show Result Card ────────────────────────────────────────────
function showResult(result) {
  const card = document.getElementById('resultCard');
  const icon = document.getElementById('resultIcon');
  const title = document.getElementById('resultTitle');
  const sub = document.getElementById('resultSubtitle');
  const bar = document.getElementById('barFill');
  const conf = document.getElementById('confidenceNum');
  const findings = document.getElementById('findings');

  card.classList.remove('hidden');
  setTimeout(() => card.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);

  const map = {
    fake:      { icon:'🚨', label:'LIKELY FAKE',  sub:'Do NOT release goods. Verify before accepting.', cls:'fake' },
    real:      { icon:'✅', label:'LOOKS REAL',    sub:'Patterns match. Confirm in your banking app.', cls:'real' },
    uncertain: { icon:'⚠️', label:'UNCERTAIN',     sub:'Not enough info. Use USSD dial or banking app.', cls:'warn' },
  };
  const m = map[result.verdict] || map.uncertain;

  icon.textContent = m.icon; icon.className = `result-icon ${m.cls}`;
  title.textContent = m.label; title.className = `result-title ${m.cls}`;
  sub.textContent = m.sub;
  bar.className = `bar-fill ${m.cls}`; bar.style.width = result.confidence + '%';
  conf.textContent = result.confidence + '%';
  card.style.setProperty('--border-glow', m.cls === 'fake' ? 'rgba(255,77,106,0.3)' : m.cls === 'real' ? 'rgba(0,212,170,0.3)' : 'rgba(245,158,11,0.3)');
  card.style.borderColor = m.cls === 'fake' ? 'rgba(255,77,106,0.3)' : m.cls === 'real' ? 'rgba(0,212,170,0.3)' : 'rgba(245,158,11,0.3)';

  findings.innerHTML = '<div class="findings-title">What we found</div>' +
    result.findings.map(f => `<div class="finding-item"><div class="finding-dot ${f.type}"></div><div class="finding-text">${f.text}</div></div>`).join('');
}

// ── Voice ───────────────────────────────────────────────────────
function speakAlert(text) {
  if (!state.voiceEnabled || !('speechSynthesis' in window)) return;
  window.speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.rate = 1.0; u.pitch = 1.0; u.lang = 'en-NG';
  window.speechSynthesis.speak(u);
}

function toggleVoice() {
  state.voiceEnabled = !state.voiceEnabled;
  const btn = document.getElementById('voiceBtn');
  document.getElementById('voiceIcon').textContent = state.voiceEnabled ? '🔊' : '🔇';
  btn.style.opacity = state.voiceEnabled ? '1' : '0.4';
  showToast(state.voiceEnabled ? 'Voice alerts ON' : 'Voice alerts OFF', 'info');
}

// ── Ledger ──────────────────────────────────────────────────────
function addLedger(amount, type) {
  const ledger = JSON.parse(localStorage.getItem('vng_ledger') || '[]');
  ledger.unshift({ amount: parseFloat(amount) || 0, type, time: new Date().toISOString() });
  localStorage.setItem('vng_ledger', JSON.stringify(ledger));
}

function updateLedgerSummary() {
  const today = new Date().toDateString();
  const ledger = JSON.parse(localStorage.getItem('vng_ledger') || '[]');
  const todayE = ledger.filter(e => new Date(e.time).toDateString() === today);
  const verified = todayE.filter(e => e.type === 'verified').reduce((s, e) => s + e.amount, 0);
  const blocked = todayE.filter(e => e.type === 'blocked').length;
  const el1 = document.getElementById('todaySales');
  const el2 = document.getElementById('blockedCount');
  if (el1) el1.textContent = '₦' + verified.toLocaleString('en-NG', { minimumFractionDigits: 2 });
  if (el2) el2.textContent = blocked + ' Blocked';
}

function renderLedger() {
  const today = new Date().toDateString();
  const ledger = JSON.parse(localStorage.getItem('vng_ledger') || '[]');
  const el = document.getElementById('ledgerList');
  if (!el) return;
  const entries = ledger.filter(e => new Date(e.time).toDateString() === today);
  if (!entries.length) { el.innerHTML = '<div class="empty-state">No transactions today.<br/>Scan an alert to start tracking.</div>'; return; }
  el.innerHTML = entries.map(e => `
    <div class="ledger-row">
      <span class="ledger-badge ${e.type}">${e.type === 'verified' ? '✅ Verified' : '🚨 Blocked'}</span>
      <span class="ledger-time">${new Date(e.time).toLocaleTimeString('en-NG', { hour:'2-digit', minute:'2-digit' })}</span>
      <span class="ledger-amt ${e.type === 'verified' ? 'green' : 'red'}">${e.type === 'verified' ? '+' : ''}₦${parseFloat(e.amount||0).toLocaleString('en-NG')}</span>
    </div>`).join('');
}

// ── History ─────────────────────────────────────────────────────
function renderHistory() {
  const el = document.getElementById('historyList');
  if (!el) return;
  if (!state.scanHistory.length) { el.innerHTML = '<div class="empty-state">No scans yet.<br/>Paste an alert to get started.</div>'; return; }
  el.innerHTML = state.scanHistory.map(h => `
    <div class="history-item">
      <span class="h-badge ${h.verdict}">${h.verdict==='fake'?'🚨 FAKE':h.verdict==='real'?'✅ REAL':'⚠️ UNSURE'}</span>
      <span class="h-preview">${h.preview}...</span>
      <span class="h-time">${h.time}</span>
    </div>`).join('');
}

// ── Share ────────────────────────────────────────────────────────
function shareResult() {
  if (!state.lastResult) return;
  const emoji = { fake:'🚨', real:'✅', uncertain:'⚠️' }[state.lastResult.verdict] || '⚠️';
  const msg = `${emoji} VerifyNG Result: ${state.lastResult.verdict.toUpperCase()} (${state.lastResult.confidence}% confidence)\n\nAlert text:\n"${(state.lastResult.text||'').substring(0,120)}..."\n\n🔍 Scan your own alerts FREE:\nVerifyNG App`;
  if (navigator.share) navigator.share({ title: 'VerifyNG Result', text: msg });
  else window.open(`https://wa.me/?text=${encodeURIComponent(msg)}`, '_blank');
}

// ── UI Helpers ───────────────────────────────────────────────────
function showScanning(show, msg = '') {
  document.getElementById('scanningAnim').classList.toggle('hidden', !show);
  if (show) { document.getElementById('scanningMsg').textContent = msg; document.getElementById('resultCard').classList.add('hidden'); }
}

function updateScanMsg(t) { const el = document.getElementById('scanningMsg'); if (el) el.textContent = t; }

function showToast(msg, type = 'info') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = `toast toast-${type} visible`;
  setTimeout(() => t.classList.remove('visible'), 3000);
}

function selectBank(el, bank) {
  document.querySelectorAll('.bank-chip').forEach(c => c.classList.remove('selected'));
  state.selectedBank = state.selectedBank === bank ? null : bank;
  if (state.selectedBank) el.classList.add('selected');
}

function clearAll() {
  document.getElementById('alertInput').value = '';
  document.getElementById('resultCard').classList.add('hidden');
  document.querySelectorAll('.bank-chip').forEach(c => c.classList.remove('selected'));
  const p = document.getElementById('imagePreview'), ph = document.getElementById('uploadPlaceholder');
  if (p) { p.src = ''; p.classList.add('hidden'); }
  if (ph) ph.classList.remove('hidden');
  state.selectedBank = null;
}

function switchTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('[data-tab]').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelectorAll(`[data-tab="${name}"]`).forEach(b => b.classList.add('active'));
  if (name === 'history') renderHistory();
  if (name === 'ledger') renderLedger();
}

function switchScanMode(mode) {
  document.getElementById('photoSection').classList.toggle('hidden', mode !== 'photo');
  document.getElementById('textSection').classList.toggle('hidden', mode !== 'text');
  document.getElementById('modePhotoBtn').classList.toggle('mode-active', mode === 'photo');
  document.getElementById('modeTextBtn').classList.toggle('mode-active', mode === 'text');
}

// ── PWA Install ──────────────────────────────────────────────────
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault(); state.deferredInstall = e;
  document.getElementById('installBanner').classList.remove('hidden');
});

function installPWA() {
  if (!state.deferredInstall) return;
  state.deferredInstall.prompt();
  state.deferredInstall.userChoice.then(() => { document.getElementById('installBanner').classList.add('hidden'); state.deferredInstall = null; });
}

// ── Init ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('totalChecks').textContent = state.totalChecks;
  const today = new Date().toDateString();
  const daily = JSON.parse(localStorage.getItem('vng_daily') || '{}');
  const todayCount = daily.date === today ? daily.count : 0;
  document.getElementById('scanCountBadge').textContent = `${todayCount}/${CONFIG.FREE_SCANS_PER_DAY} today`;
  updateLedgerSummary();

  document.getElementById('cameraInput').addEventListener('change', handleImageUpload);
  document.getElementById('galleryInput').addEventListener('change', handleImageUpload);
  document.getElementById('alertInput').addEventListener('keydown', e => { if (e.ctrlKey && e.key === 'Enter') runScan(); });

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
});
