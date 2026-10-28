// Background service worker for CyberSec Shield extension

const DEFAULT_SETTINGS = {
  serverUrl: 'http://localhost:5000',
  apiKey: ''
};

// Check and update tab badge
async function evaluateUrlForTab(tabId, url) {
  if (!url || !url.startsWith('http')) {
    chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }

  try {
    const config = await chrome.storage.sync.get(DEFAULT_SETTINGS);
    const endpoint = `${config.serverUrl.replace(/\/$/, '')}/api/v1/scan-url`;

    const headers = { 'Content-Type': 'application/json' };
    if (config.apiKey) {
      headers['X-API-Key'] = config.apiKey;
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`API returned HTTP ${response.status}`);
    }

    const data = await response.json();
    const risk = data.risk_score || 0;

    // Save scan to local storage cache for popup
    await chrome.storage.local.set({ [`scan_${tabId}`]: data });

    // Set badge text & color based on risk score
    if (risk < 35) {
      chrome.action.setBadgeText({ tabId, text: `${Math.round(risk)}` });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' }); // Green / Safe
    } else if (risk < 65) {
      chrome.action.setBadgeText({ tabId, text: 'WARN' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' }); // Amber / Warn
    } else {
      chrome.action.setBadgeText({ tabId, text: 'PHISH' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' }); // Red / Phish
    }
  } catch (err) {
    console.warn('Could not contact CyberSec API:', err);
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748b' });
  }
}

// Tab navigation listeners
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    evaluateUrlForTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  if (tab && tab.url) {
    evaluateUrlForTab(activeInfo.tabId, tab.url);
  }
});
