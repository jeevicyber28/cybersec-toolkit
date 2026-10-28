document.addEventListener('DOMContentLoaded', async () => {
  const serverInput = document.getElementById('serverUrl');
  const apiInput = document.getElementById('apiKey');
  const saveBtn = document.getElementById('saveBtn');
  const statusEl = document.getElementById('status');

  // Load saved config
  const config = await chrome.storage.sync.get({
    serverUrl: 'http://localhost:5000',
    apiKey: ''
  });

  serverInput.value = config.serverUrl;
  apiInput.value = config.apiKey;

  saveBtn.addEventListener('click', async () => {
    const serverUrl = serverInput.value.trim() || 'http://localhost:5000';
    const apiKey = apiInput.value.trim();

    await chrome.storage.sync.set({ serverUrl, apiKey });
    statusEl.innerHTML = '<span style="color: #10b981;">✅ Settings saved successfully!</span>';
    setTimeout(() => { statusEl.innerHTML = ''; }, 3000);
  });
});
