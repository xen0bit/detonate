/**
 * Dashboard Page - Load and render dashboard statistics
 * Single efficient API call, calculates all stats client-side
 */

// Chart instance
let activityChart = null;

// AbortController for canceling in-flight requests
let dashboardAbortController = null;

// Debounce timer for chart rendering
let chartRenderTimeout = null;

/**
 * Shared analysis cache - populated once, reused by all dashboard functions
 */
let cachedAnalyses = null;

/**
 * Dashboard Page - Load and render dashboard statistics
 * Single API fetch with per_page=1000, calculates all stats client-side
 */
async function loadDashboardStats() {
  const totalEl = document.getElementById('stat-total');
  const completedEl = document.getElementById('stat-completed');
  const runningEl = document.getElementById('stat-running');
  const failedEl = document.getElementById('stat-failed');

  // Guard: utility functions must exist
  if (typeof escapeHtml !== 'function') {
    console.error('dashboard.js: escapeHtml utility not loaded');
    setAllStats(totalEl, completedEl, runningEl, failedEl, 'Error');
    return;
  }

  // Cancel any in-flight request
  if (dashboardAbortController) {
    dashboardAbortController.abort();
  }
  dashboardAbortController = new AbortController();

  try {
    const response = await fetch(`${API_BASE}/reports?per_page=100`, {
      signal: dashboardAbortController.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const analyses = data.items || data.analyses || [];

    // Cache for reuse by other dashboard functions
    cachedAnalyses = analyses;

    // Calculate stats client-side
    const total = analyses.length;
    const completed = analyses.filter(a => a.status === 'completed').length;
    const running = analyses.filter(a => a.status === 'running' || a.status === 'pending').length;
    const failed = analyses.filter(a => a.status === 'failed').length;

    // Update DOM with escapeHtml for safety
    setAllStats(totalEl, completedEl, runningEl, failedEl, {
      total: String(total),
      completed: String(completed),
      running: String(running),
      failed: String(failed),
    });

  } catch (error) {
    if (error.name === 'AbortError') {
      return; // Request was canceled, ignore
    }
    console.error('Failed to load dashboard stats:', error);
    setAllStats(totalEl, completedEl, runningEl, failedEl, 'Error');
  }
}

/**
 * Helper to set all stat elements safely
 */
function setAllStats(totalEl, completedEl, runningEl, failedEl, values) {
  const escape = typeof escapeHtml === 'function' ? escapeHtml : String;
  const errorVal = 'Error';

  if (typeof values === 'string') {
    // Error case - all show the same error string
    if (totalEl) totalEl.textContent = escape(values);
    if (completedEl) completedEl.textContent = escape(values);
    if (runningEl) runningEl.textContent = escape(values);
    if (failedEl) failedEl.textContent = escape(values);
  } else {
    // Success case - values is an object with individual counts
    if (totalEl) totalEl.textContent = escape(values.total);
    if (completedEl) completedEl.textContent = escape(values.completed);
    if (runningEl) runningEl.textContent = escape(values.running);
    if (failedEl) failedEl.textContent = escape(values.failed);
  }
}

/**
 * Load and render recent analyses table
 * Reuses cachedAnalyses from loadDashboardStats() to avoid extra API call
 * Column order matches HTML thead: Session ID, Filename, Platform, Status, Techniques, Created
 */
async function loadRecentAnalyses() {
  const tableBody = document.getElementById('recent-analyses');
  if (!tableBody) return;

  // Guard: utility functions must exist
  if (typeof escapeHtml !== 'function') {
    console.error('dashboard.js: escapeHtml utility not loaded');
    tableBody.innerHTML = '<tr><td colspan="6">Error: utilities not loaded</td></tr>';
    return;
  }

  // Wait for cache to be populated (or use existing)
  if (!cachedAnalyses) {
    // If cache is empty, wait briefly for loadDashboardStats to complete
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  const analyses = cachedAnalyses || [];
  const recent = analyses.slice(0, 10);

  if (recent.length === 0) {
    tableBody.innerHTML = '<tr><td colspan="6">No analyses yet</td></tr>';
    return;
  }

  // Build table rows using createElement for safe DOM construction
  tableBody.innerHTML = '';
  recent.forEach(analysis => {
    const row = document.createElement('tr');

    // 1. Session ID (truncated) - matches HTML thead column 1
    const sessionIdCell = document.createElement('td');
    const sessionIdLink = document.createElement('a');
    sessionIdLink.href = `/web/analysis.html?id=${escapeHtml(analysis.session_id)}`;
    sessionIdLink.textContent = analysis.session_id.slice(0, 8) + '...';
    sessionIdCell.appendChild(sessionIdLink);
    row.appendChild(sessionIdCell);

    // 2. Filename - matches HTML thead column 2
    const filenameCell = document.createElement('td');
    filenameCell.textContent = escapeHtml(analysis.filename || 'unknown');
    row.appendChild(filenameCell);

    // 3. Platform - matches HTML thead column 3
    const platformCell = document.createElement('td');
    platformCell.textContent = escapeHtml(analysis.platform || 'unknown');
    row.appendChild(platformCell);

    // 4. Status badge - matches HTML thead column 4
    const statusCell = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `badge ${escapeHtml(analysis.status)}`;
    badge.textContent = escapeHtml(analysis.status);
    statusCell.appendChild(badge);
    row.appendChild(statusCell);

    // 5. Techniques count - matches HTML thead column 5
    const techniquesCell = document.createElement('td');
    techniquesCell.textContent = String(analysis.techniques_count || 0);
    row.appendChild(techniquesCell);

    // 6. Created timestamp - matches HTML thead column 6
    const timeCell = document.createElement('td');
    timeCell.textContent = formatRelativeTime(analysis.created_at);
    row.appendChild(timeCell);

    tableBody.appendChild(row);
  });
}

/**
 * Render activity chart for last 30 days
 * Reuses cachedAnalyses, debounced rendering, respects dark mode
 */
async function renderActivityChart() {
  const canvas = document.getElementById('activity-chart');
  if (!canvas) return;

  // Guard: Chart.js must be loaded
  if (typeof Chart === 'undefined') {
    console.error('dashboard.js: Chart.js not loaded');
    return;
  }

  // Guard: getTheme utility must exist
  if (typeof getTheme !== 'function') {
    console.error('dashboard.js: getTheme utility not loaded');
    return;
  }

  // Wait for cache to be populated
  if (!cachedAnalyses) {
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  const analyses = cachedAnalyses || [];

  // Calculate last 30 days activity
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const dailyCounts = {};

  // Initialize all 30 days with zero
  for (let i = 29; i >= 0; i--) {
    const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
    const dateStr = date.toISOString().split('T')[0];
    dailyCounts[dateStr] = 0;
  }

  // Count analyses per day
  analyses.forEach(analysis => {
    if (!analysis.created_at) return;
    const analysisDate = new Date(analysis.created_at);
    if (analysisDate >= thirtyDaysAgo) {
      const dateStr = analysisDate.toISOString().split('T')[0];
      if (Object.prototype.hasOwnProperty.call(dailyCounts, dateStr)) {
        dailyCounts[dateStr]++;
      }
    }
  });

  // Prepare chart data
  const labels = Object.keys(dailyCounts).map(date => {
    const d = new Date(date);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  });
  const data = Object.values(dailyCounts);

  // Clear any pending render timeout
  if (chartRenderTimeout) {
    clearTimeout(chartRenderTimeout);
  }

  // Debounce chart rendering
  chartRenderTimeout = setTimeout(() => {
    const ctx = canvas.getContext('2d');
    const theme = getTheme();
    const isDark = theme === 'dark';

    // Destroy existing chart if present
    if (activityChart) {
      activityChart.destroy();
    }

    activityChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Analyses',
          data: data,
          borderColor: isDark ? '#ff6b6b' : '#d32f2f',
          backgroundColor: isDark ? 'rgba(255, 107, 107, 0.1)' : 'rgba(211, 47, 47, 0.1)',
          tension: 0.4,
          fill: true,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false,
          },
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
              color: isDark ? '#aaa' : '#666',
            },
            grid: {
              color: isDark ? '#333' : '#eee',
            },
          },
          x: {
            ticks: {
              maxRotation: 45,
              minRotation: 45,
              color: isDark ? '#aaa' : '#666',
            },
            grid: {
              display: false,
            },
          },
        },
      },
    });
  }, 100);
}

/**
 * Cleanup on page unload - cancel requests and clear timeouts
 */
window.addEventListener('beforeunload', () => {
  if (dashboardAbortController) {
    dashboardAbortController.abort();
  }
  if (chartRenderTimeout) {
    clearTimeout(chartRenderTimeout);
  }
});

/**
 * Initialize dashboard on page load
 */
document.addEventListener('DOMContentLoaded', () => {
  // Initialize theme first
  if (typeof initTheme === 'function') {
    initTheme();
  }

  // Load all dashboard data
  loadDashboardStats();
  loadRecentAnalyses();
  renderActivityChart();
});
