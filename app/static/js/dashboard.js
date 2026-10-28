// Dashboard Chart.js Visualizations
function initDashboardCharts(metrics) {
  if (!metrics) return;

  // 1. Donut Chart - Verdict Distribution
  const donutCanvas = document.getElementById('verdictDonutChart');
  if (donutCanvas && window.Chart) {
    const verdictCounts = metrics.verdict_counts || { Safe: 5, Suspicious: 2, Malicious: 1 };
    
    new Chart(donutCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Safe / Strong', 'Suspicious', 'Malicious / Pwned'],
        datasets: [{
          data: [
            verdictCounts['Safe'] || 0,
            verdictCounts['Suspicious'] || 0,
            verdictCounts['Malicious'] || 0
          ],
          backgroundColor: [
            '#10b981', // emerald
            '#f59e0b', // amber
            '#ef4444'  // rose/red
          ],
          borderWidth: 2,
          borderColor: document.documentElement.getAttribute('data-theme') === 'dark' ? '#141c2e' : '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              boxWidth: 14,
              font: { family: 'Inter', size: 12 }
            }
          }
        },
        cutout: '68%'
      }
    });
  }

  // 2. Weekly Activity Chart - Bar + Line
  const weeklyCanvas = document.getElementById('weeklyActivityChart');
  if (weeklyCanvas && window.Chart) {
    const weeklyData = metrics.weekly || {
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
      scans: [2, 5, 3, 8, 4, 6, 7],
      safety_ratings: [90, 85, 80, 88, 92, 86, 89]
    };

    new Chart(weeklyCanvas, {
      type: 'bar',
      data: {
        labels: weeklyData.labels,
        datasets: [
          {
            type: 'bar',
            label: 'Scans Performed',
            data: weeklyData.scans,
            backgroundColor: 'rgba(99, 102, 241, 0.45)',
            borderColor: '#6366f1',
            borderWidth: 1.5,
            borderRadius: 6,
            yAxisID: 'y'
          },
          {
            type: 'line',
            label: 'Avg Safety Rating (%)',
            data: weeklyData.safety_ratings,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            fill: false,
            tension: 0.35,
            borderWidth: 2.5,
            pointBackgroundColor: '#10b981',
            pointRadius: 4,
            yAxisID: 'y1'
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            type: 'linear',
            display: true,
            position: 'left',
            beginAtZero: true,
            ticks: { stepSize: 2 }
          },
          y1: {
            type: 'linear',
            display: true,
            position: 'right',
            min: 0,
            max: 100,
            grid: { drawOnChartArea: false },
            ticks: {
              callback: function(val) { return val + '%'; }
            }
          }
        },
        plugins: {
          legend: {
            position: 'top',
            labels: {
              boxWidth: 12,
              font: { family: 'Inter', size: 12 }
            }
          }
        }
      }
    });
  }
}
