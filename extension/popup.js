// Popup interaction logic
document.addEventListener('DOMContentLoaded', async () => {
  const urlBox = document.getElementById('activeUrlBox');
  const verdictBadge = document.getElementById('verdictBadge');
  const verdictSub = document.getElementById('verdictSub');
  const scoreVal = document.getElementById('scoreVal');
  const reasonsSection = document.getElementById('reasonsSection');
  const reasonsList = document.getElementById('reasonsList');
  const rescanBtn = document.getElementById('rescanBtn');

  // Query active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    urlBox.textContent = 'No active webpage';
    return;
  }

  urlBox.textContent = tab.url;

  // Retrieve cached scan
  async function loadScanData(forceRefresh = false) {
    if (!forceRefresh) {
      const cached = await chrome.storage.local.get(`scan_${tab.id}`);
      if (cached[`scan_${tab.id}`]) {
        renderScanResult(cached[`scan_${tab.id}`]);
        return;
      }
    }

    // Direct scan
    verdictBadge.textContent = 'Scanning...';
    verdictBadge.className = 'badge';
    scoreVal.textContent = '..';

    try {
      const config = await chrome.storage.sync.get({
        serverUrl: 'http://localhost:5000',
        apiKey: ''
      });

      const endpoint = `${config.serverUrl.replace(/\/$/, '')}/api/v1/scan-url`;
      const headers = { 'Content-Type': 'application/json' };
      if (config.apiKey) headers['X-API-Key'] = config.apiKey;

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({ url: tab.url })
      });

      const data = await res.json();
      await chrome.storage.local.set({ [`scan_${tab.id}`]: data });
      renderScanResult(data);
    } catch (err) {
      verdictBadge.textContent = 'Offline';
      verdictBadge.className = 'badge badge-warn';
      verdictSub.textContent = 'Check if local server is running on :5000';
      scoreVal.textContent = '--';
    }
  }

  function renderScanResult(data) {
    const risk = data.risk_score || 0;
    scoreVal.textContent = Math.round(risk);

    if (risk < 35) {
      verdictBadge.textContent = 'Safe';
      verdictBadge.className = 'badge badge-safe';
      verdictSub.textContent = 'Legitimate structural markers verified';
      scoreVal.style.color = '#10b981';
    } else if (risk < 65) {
      verdictBadge.textContent = 'Suspicious';
      verdictBadge.className = 'badge badge-warn';
      verdictSub.textContent = 'Unusual structure or unverified domain';
      scoreVal.style.color = '#f59e0b';
    } else {
      verdictBadge.textContent = 'Phishing';
      verdictBadge.className = 'badge badge-danger';
      verdictSub.textContent = 'High-risk malicious patterns detected';
      scoreVal.style.color = '#ef4444';
    }

    if (data.top_contributions && data.top_contributions.length > 0) {
      reasonsSection.style.display = 'block';
      reasonsList.innerHTML = data.top_contributions.slice(0, 3).map(item => `
        <li><b>${item.label}:</b> <code>${item.value}</code></li>
      `).join('');
    }
  }

  if (rescanBtn) {
    rescanBtn.addEventListener('click', () => loadScanData(true));
  }

  loadScanData();
});
