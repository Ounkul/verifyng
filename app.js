// ================================================================
// VerifyNG - Main Application Logic v1.1
// Fake Alert Scanner for Nigerian Traders & POS Agents
// ================================================================

const CONFIG = { FREE_SCANS_PER_DAY: 5 };

const state = {
  voiceEnabled: true,
  selectedBank: null,
  scanHistory: JSON.parse(localStorage.getItem('vng_history') || '[]'),
  totalChecks: parseInt(localStorage.getItem('vng_checks') || '0'),
  lastResult: null,
  deferredInstall: null,
};

// ── Nigerian Bank & Fintech Patterns ───────────────────────────
const BANKS = {
  gtbank:     { name:'GTBank',       senders:['gtbank','gt bank','guaranty'],             keys:['acct','bal:','ref:','ngn','cr:','dr:'] },
  access:     { name:'Access Bank',  senders:['access','accessbank','access bank'],        keys:['credit','debit','balance','ref','acct'] },
  zenith:     { name:'Zenith Bank',  senders:['zenith','zenithbank','zenith bank'],        keys:['credit','debit','avail bal','ref'] },
  firstbank:  { name:'FirstBank',    senders:['firstbank','first bank','fbn'],             keys:['credit','debit','available balance','ref'] },
  uba:        { name:'UBA',          senders:['uba','united bank'],                        keys:['credit','debit','balance','ref'] },
  fidelity:   { name:'Fidelity Bank',senders:['fidelity','fidelitysms','fidelity bank'],  keys:['cr:','bal:','acct','dt:','desc:'] },
  fcmb:       { name:'FCMB',         senders:['fcmb'],                                    keys:['credit','debit','ref','balance'] },
  sterling:   { name:'Sterling',     senders:['sterling','sterling bank'],                 keys:['credit','debit','bal'] },
  stanbic:    { name:'Stanbic IBTC', senders:['stanbic','stanbicibtc'],                   keys:['credit','debit','balance'] },
  opay:       { name:'OPay',         senders:['opay','o-pay'],                             keys:['successful','transaction','recipient','sender','session'] },
  kuda:       { name:'Kuda',         senders:['kuda','kuda bank'],                         keys:['credit','debit','balance','ref'] },
  palmpay:    { name:'PalmPay',      senders:['palmpay','palm pay'],                       keys:['successful','transaction','recipient','transfer'] },
  moniepoint: { name:'Moniepoint',   senders:['moniepoint','teamapt','monie point'],       keys:['successful','transaction','credit','debit','ref'] },
  momo:       { name:'MoMo (MTN)',   senders:['momo','mtn momo','mtn mobile money'],      keys:['successful','transaction','recipient','transfer'] },
  wema:       { name:'Wema/ALAT',    senders:['wema','alat'],                              keys:['credit','debit','balance'] },
  union:      { name:'Union Bank',   senders:['unionbank','union bank'],                   keys:['credit','debit','balance'] },
  ecobank:    { name:'Ecobank',      senders:['ecobank'],                                  keys:['credit','debit','balance'] },
};

// ── Fake Alert Signatures ──────────────────────────────────────
// IMPORTANT: phone number regex uses word boundaries so it
// does NOT trigger inside long transaction IDs or account numbers
const FAKE_SIG = [
  {
    p: /(?<!\d)(0[789]\d{9})(?!\d)/,
    w: 40,
    t: 'Sender appears to be a personal mobile number — real bank alerts use shortcodes, not phone numbers'
  },
  {
    p: /\b(crédited|recieved|ammount|tranfer|payed|succesfull|creditted|debitted|transfered|recived|widthdraw)\b/i,
    w: 35,
    t: 'Spelling mistake detected — Nigerian banks and fintechs never misspell official messages'
  },
  {
    p: /click here|visit link|verify your account|confirm your details|http:\/\//i,
    w: 45,
    t: 'Contains suspicious link or call-to-action — real bank alerts never include these'
  },
  {
    p: /congratulations|you have won|lucky winner|prize|reward/i,
    w: 55,
    t: 'Contains lottery/prize language — this is a classic scam pattern'
  },
  {
    p: /\bpin\b|\bpassword\b|\botp\b|\bsecret\b|\btoken\b/i,
    w: 65,
    t: 'Asks for PIN/OTP/password — real bank and fintech alerts NEVER do this'
  },
  {
    p: /flash\s?transfer|fake\s?alert|test\s?transfer/i,
    w: 80,
    t: 'Contains keywords associated with fake alert generator apps'
  },
];

// ── Real Alert Signatures ──────────────────────────────────────
const REAL_SIG = [
  // SMS alert patterns
  {
    p: /\*{2,}\d{3,6}/,
    w: 20,
    t: 'Account number is properly masked (e.g. **5117 or ****726) — standard bank practice'
  },
  {
    p: /\b(ref|rrn|tran\s?id|session\s?id|transaction\s?n[o.])[:\s]*[\w\d]{6,}/i,
    w: 25,
    t: 'Contains valid transaction reference or session ID number'
  },
  {
    p: /\d{2}[\/\-][a-z]{3}[\/\-]\d{2,4}|\d{2}[\/\-]\d{2}[\/\-]\d{2,4}/i,
    w: 15,
    t: 'Date format matches standard Nigerian bank/fintech timestamp'
  },
  {
    p: /bal[:\s]+[n₦ngn]/i,
    w: 12,
    t: 'Contains balance notation (Bal: ₦...) used in real bank SMS alerts'
  },
  {
    p: /[₦n][\d,]+\.\d{2}/i,
    w: 14,
    t: 'Amount includes 2 decimal places (₦200.00 / N35,986.95) — standard bank format'
  },
  {
    p: /\b(cr:|dr:|credit[ed]*\b|debit[ed]*\b)/i,
    w: 10,
    t: 'Uses standard CR/DR credit-debit notation found in real bank alerts'
  },
  // Mobile bank / fintech RECEIPT patterns
  {
    p: /transaction\s+receipt/i,
    w: 28,
    t: 'Document is a Transaction Receipt — matches real OPay/PalmPay/Moniepoint format'
  },
  {
    p: /transaction\s+n[o.][:\s]*\d{10,}/i,
    w: 30,
    t: 'Contains valid Transaction Number in the correct receipt format'
  },
  {
    p: /session\s+id[:\s]*\d{10,}/i,
    w: 28,
    t: 'Contains Session ID — present in all genuine OPay and Moniepoint receipts'
  },
  {
    p: /recipient\s+details|sender\s+details/i,
    w: 20,
    t: 'Has Recipient/Sender Details structure — matches real mobile bank receipts'
  },
  {
    p: /\bsuccessful\b/i,
    w: 12,
    t: 'Transaction status shows "Successful"'
  },
  {
    p: /momo payment service bank|moniepoint microfinance|opay digital|kuda microfinance/i,
    w: 22,
    t: 'Contains official registered Nigerian fintech bank name'
  },
];

// ── Smart Amount Extractor ─────────────────────────────────────
// Reads ₦200.00, N0.75, NGN 50,000.00, CR:N0.75, etc.
// AVOIDS reading account numbers (10 digits) or transaction IDs (15+) as amounts
function extractAmount(text) {
  // Priority 1: ₦ symbol with amount (most reliable)
  const m1 = text.match(/[₦#N]\s*([\d,]{1,9}\.\d{2})/);
  if (m1) {
    const val = parseFloat(m1[1].replace(/,/g, ''));
    if (val > 0 && val < 999999999) return val;
  }

  // Priority 2: NGN prefix
  const m2 = text.match(/NGN\s*([\d,]{1,9}(?:\.\d{2})?)/i);
  if (m2) {
    const val = parseFloat(m2[1].replace(/,/g, ''));
    if (val > 0 && val < 999999999) return val;
  }

  // Priority 3: CR: or Amount label before number
  const m3 = text.match(/(?:CR:|CREDIT[ED]*|AMOUNT)[:\s]+[₦N]?\s*([\d,]{1,9}(?:\.\d{2})?)/i);
  if (m3) {
    const val = parseFloat(m3[1].replace(/,/g, ''));
    if (val > 0 && val < 999999999) return val;
  }

  // Priority 4: Standalone decimal number that's NOT an account/transaction ID
  // Must be ≤ 9 digits before decimal, must have decimal point
  const matches = [...text.matchAll(/(?<!\d)([\d,]{1,9}\.\d{2})(?!\d)/g)];
  for (const m of matches) {
    const val = parseFloat(m[1].replace(/,/g, ''));
    if (val > 0 && val < 999999999) return val;
  }

  return null;
}

// ── Core Analysis Engine ───────────────────────────────────────
function analyzeText(text) {
  if (!text || text.trim().length < 10) {
    return {
      verdict: 'uncertain', confidence: 0,
      findings: [{ type: 'yellow', text: 'Text too short to analyze. Paste the full SMS or receipt text.' }]
    };
  }

  const lower = text.toLowerCase();
  let fakeScore = 0, realScore = 0;
  const findings = [];

  // Check fake patterns
  FAKE_SIG.forEach(s => {
    if (s.p.test(text)) { fakeScore += s.w; findings.push({ type: 'red', text: s.t }); }
  });

  // Check real patterns
  REAL_SIG.forEach(s => {
    if (s.p.test(text)) { realScore += s.w; findings.push({ type: 'green', text: s.t }); }
  });

  // Bank / fintech name matching
  if (state.selectedBank && BANKS[state.selectedBank]) {
    const bp = BANKS[state.selectedBank];
    const nameFound = bp.senders.some(n => lower.includes(n));
    if (!nameFound) {
      fakeScore += 25;
      findings.push({ type: 'red', text: `"${bp.name}" not mentioned — doesn't match selected bank` });
    } else {
      realScore += 15;
      findings.push({ type: 'green', text: `Bank/fintech name "${bp.name}" confirmed in message` });
    }
    const kw = bp.keys.filter(k => lower.includes(k));
    if (kw.length >= 2) {
      realScore += 12;
      findings.push({ type: 'green', text: `Contains ${kw.length} standard ${bp.name} message keywords` });
    } else if (kw.length === 0) {
      fakeScore += 12;
      findings.push({ type: 'yellow', text: `Missing expected ${bp.name} keywords — select correct bank for better accuracy` });
    }
  } else {
    // Auto-detect bank or fintech
    let detected = null;
    for (const [, bp] of Object.entries(BANKS)) {
      if (bp.senders.some(n => lower.includes(n))) {
        detected = bp.name;
        realScore += 12;
        findings.push({ type: 'green', text: `Auto-detected: ${bp.name} message format` });
        // Also check keywords for auto-detected bank
        const kw = bp.keys.filter(k => lower.includes(k));
        if (kw.length >= 2) { realScore += 10; }
        break;
      }
    }
    if (!detected) {
      findings.push({ type: 'yellow', text: 'No specific bank/fintech name auto-detected — select bank above for better accuracy' });
    }
  }

  // Length sanity check
  if (text.length < 40) {
    fakeScore += 20;
    findings.push({ type: 'yellow', text: 'Very short message — real bank/fintech alerts contain more detail' });
  }

  // Amount presence check
  const amount = extractAmount(text);
  if (!amount) {
    fakeScore += 20;
    findings.push({ type: 'red', text: 'No clear transaction amount found — all real bank alerts include an amount' });
  } else {
    realScore += 8;
    findings.push({ type: 'green', text: `Transaction amount detected: ₦${amount.toLocaleString('en-NG', { minimumFractionDigits: 2 })}` });
  }

  // Duplicate receipt check
  const snippet = text.substring(0, 40);
  if (state.scanHistory.slice(0, 10).some(r => r.preview.startsWith(snippet.substring(0, 25)))) {
    fakeScore += 20;
    findings.push({ type: 'red', text: 'This alert was scanned recently — possible duplicate/reused receipt' });
  }

  if (!findings.length) {
    findings.push({ type: 'yellow', text: 'No strong patterns found — verify directly in your banking app' });
  }

  // Verdict calculation
  const total = fakeScore + realScore;
  let verdict, confidence;
  if (total === 0) {
    verdict = 'uncertain'; confidence = 50;
  } else if (fakeScore > realScore * 1.4) {
    verdict = 'fake';
    confidence = Math.min(97, Math.round((fakeScore / total) * 100));
  } else if (realScore > fakeScore) {
    verdict = 'real';
    confidence = Math.min(93, Math.round((realScore / total) * 100));
  } else {
    verdict = 'uncertain';
    confidence = 45;
  }

  return { verdict, confidence, findings, amount };
}

// ── OCR with Tesseract ─────────────────────────────────────────
async function runOCR(imageData) {
  showScanning(true, 'Reading image text...');
  try {
    const result = await Tesseract.recognize(imageData, 'eng', {
      logger: m => {
        if (m.status === 'recognizing text') {
          updateScanMsg(`Reading image... ${Math.round(m.progress * 100)}%`);
        }
      }
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
  if (s.date !== today) {
    localStorage.setItem('vng_daily', JSON.stringify({ date: today, count: 0 }));
    return true;
  }
  if (s.count >= CONFIG.FREE_SCANS_PER_DAY) {
    showUpgradePrompt();
    return false;
  }
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
  document.getElementById('scanCountBadge').textContent = `${count}/${CONFIG.FREE_SCANS_PER_DAY} free today`;
}

function showUpgradePrompt() {
  document.getElementById('upgradeModal').classList.remove('hidden');
}

// ── Image Upload Handler ───────────────────────────────────────
async function handleImageUpload(e) {
  const file = e.target.files[0];
  if (!file || !checkLimit()) return;
  const reader = new FileReader();
  reader.onload = async ev => {
    const data = ev.target.result;
    const preview = document.getElementById('imagePreview');
    const ph = document.getElementById('uploadPlaceholder');
    preview.src = data;
    preview.style.display = 'block';
    ph.classList.add('hidden');
    const text = await runOCR(data);
    if (text) processResult(text);
  };
  reader.readAsDataURL(file);
  e.target.value = '';
}

// ── Manual SMS Scan ────────────────────────────────────────────
function runScan() {
  const text = document.getElementById('alertInput').value.trim();
  if (!text) { showToast('Paste an SMS or alert text first', 'warn'); return; }
  if (!checkLimit()) return;
  document.getElementById('scanBtn').disabled = true;
  showScanning(true, 'Checking against Nigerian bank & fintech patterns...');
  setTimeout(() => {
    processResult(text);
    showScanning(false);
    document.getElementById('scanBtn').disabled = false;
  }, 1600);
}

// ── Process & Show Result ──────────────────────────────────────
function processResult(text) {
  const result = analyzeText(text);

  showResult(result);
  bumpCount();

  // Save to history
  const entry = {
    verdict: result.verdict,
    confidence: result.confidence,
    preview: text.substring(0, 60),
    time: new Date().toLocaleTimeString('en-NG', { hour: '2-digit', minute: '2-digit' }),
    amount: result.amount,
    date: new Date().toDateString()
  };
  state.scanHistory.unshift(entry);
  if (state.scanHistory.length > 50) state.scanHistory.pop();
  localStorage.setItem('vng_history', JSON.stringify(state.scanHistory));

  // Update ledger
  if (result.verdict === 'real' && result.amount) addLedger(result.amount, 'verified');
  else if (result.verdict === 'fake') addLedger(result.amount || 0, 'blocked');
  updateLedgerSummary();

  state.lastResult = { ...result, text };

  // Voice alert
  if (state.voiceEnabled) {
    const amtStr = result.amount
      ? `₦${result.amount.toLocaleString('en-NG')} `
      : '';
    if (result.verdict === 'fake') {
      speakAlert('Warning! Fake alert suspected. Do not release goods or cash.');
    } else if (result.verdict === 'real') {
      speakAlert(`Alert looks real. ${amtStr}confirmed. Verify in your banking app to be sure.`);
    } else {
      speakAlert('Result uncertain. Please verify directly in your banking app or dial USSD.');
    }
  }
}

// ── Show Result Card ───────────────────────────────────────────
function showResult(result) {
  const card = document.getElementById('resultCard');
  card.classList.remove('hidden');
  setTimeout(() => card.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 100);

  const map = {
    fake:      { icon: '🚨', label: 'LIKELY FAKE',  sub: 'Do NOT release goods or cash. Verify before accepting.', cls: 'fake', border: 'rgba(255,77,106,.3)' },
    real:      { icon: '✅', label: 'LOOKS REAL',   sub: 'Patterns match. Always confirm in your banking app.', cls: 'real', border: 'rgba(0,212,170,.3)' },
    uncertain: { icon: '⚠️', label: 'UNCERTAIN',    sub: 'Not enough info. Use USSD tab or check your banking app.', cls: 'warn', border: 'rgba(245,158,11,.3)' },
  };
  const m = map[result.verdict] || map.uncertain;

  document.getElementById('resultIcon').textContent = m.icon;
  document.getElementById('resultIcon').className = `result-icon ${m.cls}`;
  document.getElementById('resultTitle').textContent = m.label;
  document.getElementById('resultTitle').className = `result-title ${m.cls}`;
  document.getElementById('resultSubtitle').textContent = m.sub;
  document.getElementById('barFill').className = `bar-fill ${m.cls}`;
  document.getElementById('barFill').style.width = result.confidence + '%';
  document.getElementById('confidenceNum').textContent = result.confidence + '%';
  card.style.borderColor = m.border;

  // Show amount if detected
  const amountRow = document.getElementById('detectedAmount');
  if (result.amount && amountRow) {
    amountRow.textContent = `💰 Detected Amount: ₦${result.amount.toLocaleString('en-NG', { minimumFractionDigits: 2 })}`;
    amountRow.classList.remove('hidden');
  } else if (amountRow) {
    amountRow.classList.add('hidden');
  }

  const findings = document.getElementById('findings');
  findings.innerHTML = '<div class="findings-title">What we found</div>' +
    result.findings.map(f =>
      `<div class="finding-item"><div class="finding-dot ${f.type}"></div><div class="finding-text">${f.text}</div></div>`
    ).join('');
}

// ── Voice ──────────────────────────────────────────────────────
function speakAlert(text) {
  if (!state.voiceEnabled || !('speechSynthesis' in window)) return;
  window.speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.rate = 1.0; u.pitch = 1.0; u.lang = 'en-NG';
  window.speechSynthesis.speak(u);
}

function toggleVoice() {
  state.voiceEnabled = !state.voiceEnabled;
  document.getElementById('voiceIcon').textContent = state.voiceEnabled ? '🔊' : '🔇';
  document.getElementById('voiceBtn').style.opacity = state.voiceEnabled ? '1' : '0.4';
  showToast(state.voiceEnabled ? 'Voice alerts ON' : 'Voice alerts OFF', 'info');
}

// ── Daily Ledger ───────────────────────────────────────────────
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
  if (!entries.length) {
    el.innerHTML = '<div class="empty-state">No transactions today.<br/>Scan an alert to start tracking.</div>';
    return;
  }
  el.innerHTML = entries.map(e => `
    <div class="ledger-row">
      <span class="ledger-badge ${e.type}">${e.type === 'verified' ? '✅ Verified' : '🚨 Blocked'}</span>
      <span class="ledger-time">${new Date(e.time).toLocaleTimeString('en-NG', { hour: '2-digit', minute: '2-digit' })}</span>
      <span class="ledger-amt ${e.type === 'verified' ? 'green' : 'red'}">${e.type === 'verified' ? '+' : ''}₦${parseFloat(e.amount || 0).toLocaleString('en-NG')}</span>
    </div>`).join('');
}

// ── History ────────────────────────────────────────────────────
function renderHistory() {
  const el = document.getElementById('historyList');
  if (!el) return;
  if (!state.scanHistory.length) {
    el.innerHTML = '<div class="empty-state">No scans yet.<br/>Paste an alert to get started.</div>';
    return;
  }
  el.innerHTML = state.scanHistory.map(h => `
    <div class="history-item">
      <span class="h-badge ${h.verdict}">${h.verdict === 'fake' ? '🚨 FAKE' : h.verdict === 'real' ? '✅ REAL' : '⚠️ UNSURE'}</span>
      <span class="h-preview">${h.preview}...</span>
      <span class="h-time">${h.time}</span>
    </div>`).join('');
}

// ── Share Result ───────────────────────────────────────────────
function shareResult() {
  if (!state.lastResult) return;
  const emoji = { fake: '🚨', real: '✅', uncertain: '⚠️' }[state.lastResult.verdict] || '⚠️';
  const amtStr = state.lastResult.amount
    ? `\nAmount: ₦${state.lastResult.amount.toLocaleString('en-NG', { minimumFractionDigits: 2 })}`
    : '';
  const msg = `${emoji} VerifyNG Result: ${state.lastResult.verdict.toUpperCase()} (${state.lastResult.confidence}% confidence)${amtStr}\n\nScanned text:\n"${(state.lastResult.text || '').substring(0, 120)}..."\n\n🔍 Scan your alerts FREE:\nhttps://ounkul.github.io/verifyng/`;
  if (navigator.share) navigator.share({ title: 'VerifyNG Result', text: msg });
  else window.open(`https://wa.me/?text=${encodeURIComponent(msg)}`, '_blank');
}

// ── UI Helpers ─────────────────────────────────────────────────
function showScanning(show, msg = '') {
  document.getElementById('scanningAnim').classList.toggle('hidden', !show);
  if (show) {
    document.getElementById('scanningMsg').textContent = msg;
    document.getElementById('resultCard').classList.add('hidden');
  }
}
function updateScanMsg(t) { const el = document.getElementById('scanningMsg'); if (el) el.textContent = t; }

function showToast(msg, type = 'info') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast toast-${type} visible`;
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
  const p = document.getElementById('imagePreview');
  const ph = document.getElementById('uploadPlaceholder');
  if (p) { p.src = ''; p.style.display = 'none'; }
  if (ph) ph.classList.remove('hidden');
  state.selectedBank = null;
}

function switchTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('[data-tab]').forEach(b => b.classList.remove('active'));
  const panel = document.getElementById('tab-' + name);
  if (panel) panel.classList.add('active');
  document.querySelectorAll(`[data-tab="${name}"]`).forEach(b => b.classList.add('active'));
  if (name === 'history') renderHistory();
  if (name === 'ledger') renderLedger();
}

function switchScanMode(mode) {
  const photo = document.getElementById('photoSection');
  const text = document.getElementById('textSection');
  const pBtn = document.getElementById('modePhotoBtn');
  const tBtn = document.getElementById('modeTextBtn');
  if (mode === 'photo') {
    photo.style.display = ''; text.style.display = 'none';
    pBtn.classList.add('mode-active'); tBtn.classList.remove('mode-active');
  } else {
    text.style.display = ''; photo.style.display = 'none';
    tBtn.classList.add('mode-active'); pBtn.classList.remove('mode-active');
  }
}

// ── PWA Install ────────────────────────────────────────────────
window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  state.deferredInstall = e;
  document.getElementById('installBanner').classList.remove('hidden');
});

function installPWA() {
  if (!state.deferredInstall) return;
  state.deferredInstall.prompt();
  state.deferredInstall.userChoice.then(() => {
    document.getElementById('installBanner').classList.add('hidden');
    state.deferredInstall = null;
  });
}

// ── Init ───────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Splash screen
  setTimeout(() => {
    const splash = document.getElementById('splash');
    if (splash) {
      splash.style.opacity = '0';
      splash.style.transition = 'opacity 0.5s ease';
      setTimeout(() => splash.remove(), 500);
    }
  }, 2500);

  document.getElementById('totalChecks').textContent = state.totalChecks;
  const today = new Date().toDateString();
  const daily = JSON.parse(localStorage.getItem('vng_daily') || '{}');
  const todayCount = daily.date === today ? daily.count : 0;
  document.getElementById('scanCountBadge').textContent = `${todayCount}/${CONFIG.FREE_SCANS_PER_DAY} free today`;
  updateLedgerSummary();

  document.getElementById('cameraInput').addEventListener('change', handleImageUpload);
  document.getElementById('galleryInput').addEventListener('change', handleImageUpload);
  document.getElementById('alertInput').addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter') runScan();
  });

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/verifyng/sw.js').catch(() => {});
  }
});
