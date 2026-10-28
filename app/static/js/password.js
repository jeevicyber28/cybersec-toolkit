// Zero-Knowledge Client-Side Password & Breach Auditor
document.addEventListener('DOMContentLoaded', () => {
  const pwdInput = document.getElementById('pwdInput');
  const toggleVisibility = document.getElementById('toggleVisibility');
  const checkBreachBtn = document.getElementById('checkBreachBtn');
  const saveAuditBtn = document.getElementById('saveAuditBtn');

  if (!pwdInput) return;

  // Toggle visible password
  if (toggleVisibility) {
    toggleVisibility.addEventListener('click', () => {
      pwdInput.type = pwdInput.type === 'password' ? 'text' : 'password';
      toggleVisibility.textContent = pwdInput.type === 'password' ? '👁️' : '🔒';
    });
  }

  // Real-time strength evaluator
  pwdInput.addEventListener('input', () => {
    const val = pwdInput.value;
    updateStrengthEstimate(val);
  });

  // Breach checker with k-anonymity
  if (checkBreachBtn) {
    checkBreachBtn.addEventListener('click', async () => {
      const val = pwdInput.value;
      if (!val) {
        alert('Please enter a password to audit.');
        return;
      }
      await performKAnonymityCheck(val);
    });
  }

  // Save audit summary
  if (saveAuditBtn) {
    saveAuditBtn.addEventListener('click', async () => {
      await saveAnonymousAudit();
    });
  }
});

// SHA-1 in browser memory using Web Crypto API
async function sha1(str) {
  const buffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

let lastAuditData = null;

async function performKAnonymityCheck(password) {
  const statusEl = document.getElementById('breachResult');
  const spinner = document.getElementById('breachSpinner');
  if (spinner) spinner.style.display = 'inline-block';
  if (statusEl) {
    statusEl.innerHTML = '<span class="text-muted">Computing zero-knowledge SHA-1 hash locally...</span>';
  }

  try {
    const fullHash = await sha1(password);
    const prefix = fullHash.slice(0, 5);
    const suffix = fullHash.slice(5);

    if (statusEl) {
      statusEl.innerHTML = `<span class="text-muted">Querying k-anonymity range for prefix: <code>${prefix}</code>... (never sending password)</span>`;
    }

    const response = await fetch(`/api/v1/pwned-range/${prefix}`);
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const text = await response.text();
    const lines = text.split('\n');

    let breachCount = 0;
    for (const line of lines) {
      const parts = line.trim().split(':');
      if (parts.length === 2 && parts[0].toUpperCase() === suffix) {
        breachCount = parseInt(parts[1], 10);
        break;
      }
    }

    if (spinner) spinner.style.display = 'none';

    if (breachCount > 0) {
      statusEl.innerHTML = `
        <div class="alert alert-danger" style="margin-top: 1rem;">
          ⚠️ <b>Pwned!</b> This password has been exposed <b>${breachCount.toLocaleString()} times</b> in known data breaches.<br/>
          <small>Change this password immediately across all services where it was used.</small>
        </div>
      `;
    } else {
      statusEl.innerHTML = `
        <div class="alert alert-success" style="margin-top: 1rem;">
          🛡️ <b>Clean Record!</b> This password does NOT appear in known public breach compilations (HIBP database).
        </div>
      `;
    }

    // Update state for optional save
    if (lastAuditData) {
      lastAuditData.pwned_count = breachCount;
      const saveBtn = document.getElementById('saveAuditBtn');
      if (saveBtn) saveBtn.style.display = 'inline-flex';
    }

  } catch (err) {
    if (spinner) spinner.style.display = 'none';
    if (statusEl) {
      statusEl.innerHTML = `<div class="alert alert-warning">Notice: Could not reach breach API (${err.message}). Local strength checks remain active.</div>`;
    }
  }
}

function updateStrengthEstimate(password) {
  const length = password.length;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);

  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigit) poolSize += 10;
  if (hasSymbol) poolSize += 33;

  const entropyBits = poolSize > 0 ? Math.round(length * Math.log2(poolSize) * 10) / 10 : 0;
  let score = Math.min(100, Math.round((entropyBits / 85) * 100));

  // Pattern detection
  const patterns = [];
  const pwdLower = password.toLowerCase();
  if (/(123456|qwerty|password|admin|letmein|welcome)/.test(pwdLower)) {
    patterns.push('Contains common sequence or default word');
    score = Math.max(10, score - 35);
  }
  if (/(.)\1{3,}/.test(pwdLower)) {
    patterns.push('Contains 4+ repeated identical characters');
    score = Math.max(10, score - 20);
  }

  let rating = 'Weak';
  let ratingClass = 'badge-danger';
  let barColor = '#ef4444';

  if (score >= 80 && length >= 12) {
    rating = 'Very Strong';
    ratingClass = 'badge-success';
    barColor = '#10b981';
  } else if (score >= 60 && length >= 10) {
    rating = 'Strong';
    ratingClass = 'badge-info';
    barColor = '#0ea5e9';
  } else if (score >= 40) {
    rating = 'Moderate';
    ratingClass = 'badge-warning';
    barColor = '#f59e0b';
  }

  // Update DOM elements
  const meterFill = document.getElementById('meterFill');
  const ratingBadge = document.getElementById('ratingBadge');
  const entropyVal = document.getElementById('entropyVal');
  const lengthVal = document.getElementById('lengthVal');
  const poolVal = document.getElementById('poolVal');
  const patternsList = document.getElementById('patternsList');

  if (meterFill) {
    meterFill.style.width = score + '%';
    meterFill.style.backgroundColor = barColor;
  }
  if (ratingBadge) {
    ratingBadge.textContent = rating;
    ratingBadge.className = `badge ${ratingClass}`;
  }
  if (entropyVal) entropyVal.textContent = entropyBits + ' bits';
  if (lengthVal) lengthVal.textContent = length + ' chars';
  if (poolVal) poolVal.textContent = poolSize + ' chars';

  if (patternsList) {
    if (patterns.length > 0) {
      patternsList.innerHTML = patterns.map(p => `<li>⚠️ ${p}</li>`).join('');
    } else {
      patternsList.innerHTML = '<li>✅ No predictable keyboard walks or common patterns detected.</li>';
    }
  }

  lastAuditData = {
    length: length,
    entropy_bits: entropyBits,
    score: score,
    rating: rating,
    pwned_count: 0,
    tips: []
  };
}

async function saveAnonymousAudit() {
  if (!lastAuditData) return;
  const btn = document.getElementById('saveAuditBtn');
  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    const res = await fetch('/password-checker/record-audit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
      },
      body: JSON.stringify(lastAuditData)
    });

    const data = await res.json();
    if (data.success) {
      btn.textContent = 'Saved to History!';
      setTimeout(() => { btn.style.display = 'none'; }, 2000);
    } else {
      btn.textContent = 'Save Failed';
      btn.disabled = false;
    }
  } catch (err) {
    console.error('Audit save error:', err);
    btn.textContent = 'Error';
    btn.disabled = false;
  }
}
