// Spot the Phish Awareness Game Engine
document.addEventListener('DOMContentLoaded', () => {
  const startBtn = document.getElementById('startGameBtn');
  const restartBtn = document.getElementById('restartGameBtn');
  const realBtn = document.getElementById('btnReal');
  const phishBtn = document.getElementById('btnPhish');
  const nextBtn = document.getElementById('btnNextRound');

  if (startBtn) startBtn.addEventListener('click', initGame);
  if (restartBtn) restartBtn.addEventListener('click', initGame);
  if (realBtn) realBtn.addEventListener('click', () => handleAnswer(false));
  if (phishBtn) phishBtn.addEventListener('click', () => handleAnswer(true));
  if (nextBtn) nextBtn.addEventListener('click', nextRound);
});

let gameState = {
  rounds: [],
  currentIndex: 0,
  score: 0,
  streak: 0,
  maxStreak: 0,
  correctCount: 0,
  history: []
};

async function initGame() {
  const introCard = document.getElementById('gameIntroCard');
  const quizCard = document.getElementById('gamePlayCard');
  const resultsCard = document.getElementById('gameResultsCard');
  const confetti = document.getElementById('confettiContainer');

  if (introCard) introCard.style.display = 'none';
  if (resultsCard) resultsCard.style.display = 'none';
  if (confetti) confetti.style.display = 'none';
  if (quizCard) quizCard.style.display = 'block';

  try {
    const res = await fetch('/game/rounds');
    const data = await res.json();
    
    gameState = {
      rounds: data.rounds || [],
      currentIndex: 0,
      score: 0,
      streak: 0,
      maxStreak: 0,
      correctCount: 0,
      history: []
    };

    renderCurrentRound();
  } catch (err) {
    console.error('Failed to load game rounds:', err);
    alert('Failed to load quiz items. Please try again.');
  }
}

function renderCurrentRound() {
  const item = gameState.rounds[gameState.currentIndex];
  if (!item) {
    finishGame();
    return;
  }

  // Update header counters
  document.getElementById('currentRoundNum').textContent = gameState.currentIndex + 1;
  document.getElementById('currentScore').textContent = gameState.score;
  document.getElementById('currentStreak').textContent = gameState.streak;

  const progressPct = ((gameState.currentIndex + 1) / gameState.rounds.length) * 100;
  document.getElementById('quizProgressFill').style.width = `${progressPct}%`;

  // Item category & difficulty
  const typeBadge = document.getElementById('itemTypeBadge');
  typeBadge.textContent = item.type.toUpperCase();
  typeBadge.className = `badge badge-${item.type === 'url' ? 'info' : (item.type === 'email' ? 'purple' : 'success')}`;

  const diffBadge = document.getElementById('itemDiffBadge');
  diffBadge.textContent = item.difficulty.toUpperCase();
  diffBadge.className = `badge badge-${item.difficulty === 'easy' ? 'success' : (item.difficulty === 'medium' ? 'warning' : 'danger')}`;

  // Content Preview
  const previewContainer = document.getElementById('quizItemContent');
  if (item.type === 'url') {
    previewContainer.innerHTML = `
      <div class="preview-url">
        <span>🌐</span>
        <span>${escapeHtml(item.content)}</span>
      </div>
    `;
  } else if (item.type === 'email') {
    previewContainer.innerHTML = `
      <div class="preview-email">
        ${escapeHtml(item.content)}
      </div>
    `;
  } else {
    previewContainer.innerHTML = `
      <div class="preview-sms">
        💬 <b>SMS Message:</b><br/>
        ${escapeHtml(item.content)}
      </div>
    `;
  }

  // Reset choice buttons & feedback box
  document.getElementById('btnReal').disabled = false;
  document.getElementById('btnPhish').disabled = false;
  document.getElementById('feedbackBox').style.display = 'none';
  document.getElementById('btnNextRound').style.display = 'none';
}

function handleAnswer(userChosePhish) {
  const item = gameState.rounds[gameState.currentIndex];
  const isCorrect = (userChosePhish === item.is_phish);

  // Disable buttons
  document.getElementById('btnReal').disabled = true;
  document.getElementById('btnPhish').disabled = true;

  if (isCorrect) {
    gameState.correctCount++;
    gameState.streak++;
    gameState.maxStreak = Math.max(gameState.maxStreak, gameState.streak);
    const roundScore = 100 + (gameState.streak * 15);
    gameState.score += roundScore;
  } else {
    gameState.streak = 0;
  }

  // Update score & streak
  document.getElementById('currentScore').textContent = gameState.score;
  document.getElementById('currentStreak').textContent = gameState.streak;

  // Record history
  gameState.history.push({
    item: item,
    isCorrect: isCorrect,
    explanation: item.explanation
  });

  // Display feedback
  const feedbackBox = document.getElementById('feedbackBox');
  const feedbackTitle = document.getElementById('feedbackTitle');
  const feedbackText = document.getElementById('feedbackText');

  feedbackBox.className = `feedback-box ${isCorrect ? 'feedback-correct' : 'feedback-incorrect'}`;
  feedbackTitle.innerHTML = isCorrect ? '🎯 <b>Correct! Well Spotted!</b>' : '❌ <b>Oops! You got caught!</b>';
  feedbackText.innerHTML = `
    <p><b>Actual:</b> ${item.is_phish ? '🚨 Malicious / Phishing' : '✅ Real / Legitimate'}</p>
    <p style="margin-top: 0.4rem;">${escapeHtml(item.explanation)}</p>
  `;
  feedbackBox.style.display = 'block';

  // Show Next button
  const nextBtn = document.getElementById('btnNextRound');
  nextBtn.textContent = (gameState.currentIndex + 1 >= gameState.rounds.length) ? 'See Results 🏆' : 'Next Round ➔';
  nextBtn.style.display = 'inline-flex';
}

function nextRound() {
  gameState.currentIndex++;
  if (gameState.currentIndex >= gameState.rounds.length) {
    finishGame();
  } else {
    renderCurrentRound();
  }
}

async function finishGame() {
  document.getElementById('gamePlayCard').style.display = 'none';
  const resultsCard = document.getElementById('gameResultsCard');
  resultsCard.style.display = 'block';

  const total = gameState.rounds.length;
  const correct = gameState.correctCount;
  const score = gameState.score;

  // Determine badge
  let badge = 'Rookie';
  let badgeIcon = '🥉';
  if (score >= 800) {
    badge = 'Phish Hunter';
    badgeIcon = '🥇';
  } else if (score >= 500) {
    badge = 'Defender';
    badgeIcon = '🥈';
  }

  document.getElementById('resultsTrophy').textContent = badgeIcon;
  document.getElementById('resultsBadgeName').textContent = badge;
  document.getElementById('resultsScore').textContent = score;
  document.getElementById('resultsCorrect').textContent = `${correct} / ${total}`;
  document.getElementById('resultsMaxStreak').textContent = gameState.maxStreak;

  // Dynamic tips based on mistakes
  const tipsContainer = document.getElementById('resultsTipsList');
  const mistakes = gameState.history.filter(h => !h.isCorrect);

  if (mistakes.length === 0) {
    tipsContainer.innerHTML = `
      <li>🌟 Flawless security instincts! You caught every lure and identified all authentic messages.</li>
      <li>🛡️ Always verify domain roots from right to left before submitting credentials.</li>
    `;
    // Trigger confetti if reduced motion is not preferred
    triggerConfetti();
  } else {
    tipsContainer.innerHTML = mistakes.slice(0, 4).map(m => `
      <li>⚠️ <b>${m.item.type.toUpperCase()}:</b> ${escapeHtml(m.item.explanation)}</li>
    `).join('');
  }

  // Submit to backend
  try {
    const res = await fetch('/game/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
      },
      body: JSON.stringify({
        score: score,
        max_streak: gameState.maxStreak,
        correct_answers: correct,
        total_rounds: total
      })
    });
    const data = await res.json();
    if (data.best_score) {
      document.getElementById('resultsBestScore').textContent = data.best_score;
    }
  } catch (err) {
    console.error('Failed to save score:', err);
  }
}

function triggerConfetti() {
  // Check prefers-reduced-motion media query
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return;
  }

  const container = document.getElementById('confettiContainer');
  if (!container) return;
  container.innerHTML = '';
  container.style.display = 'block';

  const colors = ['#6366f1', '#10b981', '#f59e0b', '#ec4899', '#06b6d4', '#8b5cf6'];
  const count = 40;

  for (let i = 0; i < count; i++) {
    const particle = document.createElement('div');
    particle.className = 'confetti-particle';
    particle.style.left = Math.random() * 100 + 'vw';
    particle.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
    particle.style.animationDelay = (Math.random() * 2) + 's';
    particle.style.animationDuration = (2.5 + Math.random() * 2) + 's';
    
    // Vary shapes: square, circle, ribbon
    if (i % 3 === 0) {
      particle.style.borderRadius = '50%';
    } else if (i % 3 === 1) {
      particle.style.width = '16px';
      particle.style.height = '6px';
    }
    container.appendChild(particle);
  }

  // Auto clean up after 7 seconds
  setTimeout(() => {
    container.style.display = 'none';
    container.innerHTML = '';
  }, 7000);
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
}
