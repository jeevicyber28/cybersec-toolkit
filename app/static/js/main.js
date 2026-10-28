// Main JavaScript Utilities
document.addEventListener('DOMContentLoaded', () => {
  // Theme Toggle Logic
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeIcon = document.getElementById('themeIcon');
  const themeText = document.getElementById('themeText');

  const getSavedTheme = () => {
    const saved = localStorage.getItem('cybersec_theme');
    if (saved) return saved;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  };

  const applyTheme = (theme) => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('cybersec_theme', theme);
    if (themeIcon) {
      themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
    }
    if (themeText) {
      themeText.textContent = theme === 'dark' ? 'Light' : 'Dark';
    }
  };

  // Init theme
  applyTheme(getSavedTheme());

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      applyTheme(current === 'dark' ? 'light' : 'dark');
    });
  }

  // Auto-dismiss alerts after 5 seconds
  document.querySelectorAll('.alert').forEach(alert => {
    setTimeout(() => {
      alert.style.opacity = '0';
      alert.style.transition = 'opacity 0.4s ease';
      setTimeout(() => alert.remove(), 400);
    }, 5500);
  });
});

// Copy to Clipboard Utility
function copyToClipboard(text, feedbackElementId) {
  navigator.clipboard.writeText(text).then(() => {
    const el = document.getElementById(feedbackElementId);
    if (el) {
      const originalText = el.textContent;
      el.textContent = 'Copied!';
      setTimeout(() => { el.textContent = originalText; }, 2000);
    }
  }).catch(err => {
    console.error('Clipboard copy failed:', err);
  });
}
