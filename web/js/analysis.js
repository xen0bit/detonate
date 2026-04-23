/**
 * Analysis Detail Page - Tabs, polling, techniques matrix, API calls, reports
 * 
 * Dependencies: Requires app.js to be loaded first (provides API_BASE, escapeHtml, 
 * showToast, getTheme, formatFileSize, formatAbsoluteTime, initTheme).
 */

// Dependency check - ensure app.js loaded required utilities
(function checkDependencies() {
  const required = ['API_BASE', 'escapeHtml', 'showToast', 'getTheme', 'formatFileSize', 'formatAbsoluteTime', 'initTheme'];
  const missing = required.filter(name => typeof window[name] === 'undefined');
  if (missing.length > 0) {
    console.error('analysis.js: Missing dependencies from app.js:', missing.join(', '));
    console.error('Ensure app.js is loaded before analysis.js in HTML');
  }
})();

// State
let sessionId = null;
let analysisData = null;
let pollInterval = null;
let pollAttempts = 0;
const MAX_POLL_ATTEMPTS = 120; // 10 minutes at 5s intervals

// Polling state
let isPolling = false;
let consecutiveFailures = 0;
const MAX_CONSECUTIVE_FAILURES = 3;
let pollingAbortController = null;

// API calls pagination
let apiCallsPage = 1;
let apiCallsData = [];
const apiCallsPerPage = 50;
let apiCallsTotalPages = 1;

// AbortController for canceling in-flight API calls requests
let apiCallsAbortController = null;

// Loading state for "Load More" button
let isLoadingApiCalls = false;

// Chart instance
let tacticsChart = null;

// Cached API calls for export
let allAPICalls = [];

// Pre-formatted API call rows (to avoid re-parsing JSON on every render)
let formattedAPICallRows = [];

/**
 * Get session ID from URL params
 */
function getSessionId() {
  const params = new URLSearchParams(window.location.search);
  return params.get('id');
}

/**
 * Load analysis detail data
 */
async function loadAnalysisDetail() {
  sessionId = getSessionId();
  
  if (!sessionId) {
    showError('No analysis ID provided');
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/analyze/${sessionId}`);
    
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Analysis not found');
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    analysisData = await response.json();
    renderOverview();
    
    // Start polling if running/pending
    if (analysisData.status === 'pending' || analysisData.status === 'running') {
      startPolling();
    } else {
      // Load additional data for completed analyses
      loadTechniques();
      loadAPICalls();
      loadReports();
    }

  } catch (error) {
    console.error('Failed to load analysis:', error);
    showError('Failed to load analysis: ' + error.message);
  }
}

/**
 * Show error message
 * @param {string} message - Error message
 */
function showError(message) {
  const header = document.getElementById('analysis-header');
  header.innerHTML = `
    <article style="border-left: 4px solid #d32f2f;">
      <h2>Error</h2>
      <p>${escapeHtml(message)}</p>
      <a href="/web/analyses.html" class="btn btn-outline" style="margin-top: 1rem;">Back to Analyses</a>
    </article>
  `;
  
  // Hide tabs
  document.getElementById('tabs').style.display = 'none';
  document.querySelectorAll('.tab-content').forEach(tab => tab.style.display = 'none');
}

/**
 * Render overview tab
 */
function renderOverview() {
  const data = analysisData;
  
  // Header
  document.getElementById('header-filename').textContent = data.filename || 'Unknown';
  document.getElementById('header-session').textContent = data.session_id || sessionId;
  
  const statusEl = document.getElementById('header-status');
  statusEl.textContent = data.status || 'unknown';
  statusEl.className = `badge ${data.status || 'unknown'}`;
  
  // Stats
  document.getElementById('overview-size').textContent = formatFileSize(data.file_size);
  document.getElementById('overview-platform').textContent = data.platform || 'N/A';
  document.getElementById('overview-techniques').textContent = data.techniques_count || 0;
  document.getElementById('overview-duration').textContent = formatDuration(data.started_at, data.completed_at);
  
  // Sample info
  document.getElementById('info-filename').textContent = data.filename || 'Unknown';
  document.getElementById('info-md5').textContent = data.md5 || 'N/A';
  document.getElementById('info-sha256').textContent = data.sha256 || 'N/A';
  document.getElementById('info-filetype').textContent = data.file_type || 'N/A';
  document.getElementById('info-platform').textContent = data.platform || 'N/A';
  document.getElementById('info-arch').textContent = data.arch || 'N/A';
  
  // Timeline
  document.getElementById('timeline-created').textContent = data.created_at ? formatAbsoluteTime(data.created_at) : 'N/A';
  document.getElementById('timeline-started').textContent = data.started_at ? formatAbsoluteTime(data.started_at) : 'N/A';
  document.getElementById('timeline-completed').textContent = data.completed_at ? formatAbsoluteTime(data.completed_at) : 'N/A';
  document.getElementById('timeline-duration').textContent = formatDuration(data.started_at, data.completed_at);
  
  // Summary
  const techniquesCount = data.techniques_count || 0;
  document.getElementById('overview-summary').textContent = 
    `This analysis detected ${techniquesCount} MITRE ATT&CK technique${techniquesCount !== 1 ? 's' : ''} ` +
    `with ${data.findings?.length || 0} total evidence item${data.findings?.length !== 1 ? 's' : ''}.`;
}

/**
 * Format duration between two timestamps
 * @param {string} start - Start timestamp
 * @param {string} end - End timestamp
 * @returns {string} Formatted duration
 */
function formatDuration(start, end) {
  if (!start || !end) return 'N/A';
  
  const startMs = new Date(start).getTime();
  const endMs = new Date(end).getTime();
  const diffSecs = Math.floor((endMs - startMs) / 1000);
  
  if (diffSecs < 60) return `${diffSecs}s`;
  if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ${diffSecs % 60}s`;
  return `${Math.floor(diffSecs / 3600)}h ${Math.floor((diffSecs % 3600) / 60)}m`;
}

/**
 * Load and render techniques
 */
async function loadTechniques() {
  const matrixEl = document.getElementById('techniques-matrix');
  const countEl = document.getElementById('techniques-count');
  
  // Null-safe element access
  if (!matrixEl || !countEl) {
    console.warn('loadTechniques: Required DOM elements not found');
    return;
  }
  
  try {
    const response = await fetch(`${API_BASE}/analyses/${sessionId}/findings?page=1&per_page=100`);
    
    // Handle 404 gracefully - analysis exists but has no techniques yet
    if (response.status === 404) {
      countEl.textContent = '0 found';
      matrixEl.innerHTML = '<p class="empty-state">No techniques detected</p>';
      return;
    }
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    const findings = data.items || [];
    
    countEl.textContent = `${findings.length} found`;
    renderTechniquesMatrix(findings);
    
    // Render tactics chart only if Chart.js is available and we have data
    if (findings.length > 0 && typeof Chart !== 'undefined') {
      renderTacticsChart(findings);
    }

  } catch (error) {
    console.error('Failed to load techniques:', error);
    matrixEl.innerHTML = 
      `<p class="empty-state">Failed to load techniques: ${escapeHtml(error.message)}</p>`;
  }
}

/**
 * Render techniques matrix grouped by tactic
 * @param {Array} findings - Findings data
 */
function renderTechniquesMatrix(findings) {
  const matrix = document.getElementById('techniques-matrix');
  
  if (findings.length === 0) {
    matrix.innerHTML = '<p class="empty-state">No techniques detected</p>';
    return;
  }

  // Group by tactic
  const byTactic = {};
  findings.forEach(f => {
    const tactic = f.tactic || 'Unknown';
    if (!byTactic[tactic]) {
      byTactic[tactic] = [];
    }
    byTactic[tactic].push(f);
  });

  // Sort tactics in MITRE order
  const tacticOrder = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact', 'Unknown'
  ];

  const sortedTactics = Object.keys(byTactic).sort((a, b) => {
    const aIdx = tacticOrder.indexOf(a);
    const bIdx = tacticOrder.indexOf(b);
    return (aIdx === -1 ? 999 : aIdx) - (bIdx === -1 ? 999 : bIdx);
  });

  // Build matrix HTML
  const columns = sortedTactics.map(tactic => {
    const techniques = byTactic[tactic].sort((a, b) => a.technique_id.localeCompare(b.technique_id));
    
    const techniqueItems = techniques.map(f => {
      const confidenceClass = getConfidenceClass(f.confidence_score);
      return `
        <div class="technique-item ${confidenceClass}" 
             onclick="showTechniqueModal('${escapeHtml(f.technique_id)}')">
          <strong>${escapeHtml(f.technique_id)}</strong><br>
          <span style="font-size: 0.75rem;">${escapeHtml(f.technique_name)}</span>
        </div>
      `;
    }).join('');

    return `
      <div class="tactic-column">
        <h4>${escapeHtml(tactic)}</h4>
        ${techniqueItems}
      </div>
    `;
  }).join('');

  matrix.innerHTML = columns;
}

/**
 * Get confidence class based on score
 * @param {number} score - Confidence score
 * @returns {string} CSS class
 */
function getConfidenceClass(score) {
  if (score >= 0.7) return 'high';
  if (score >= 0.4) return 'medium';
  return 'low';
}

/**
 * Show technique details modal
 * @param {string} techniqueId - Technique ID
 */
async function showTechniqueModal(techniqueId) {
  if (!analysisData || !analysisData.findings) return;
  
  const finding = analysisData.findings.find(f => f.technique_id === techniqueId);
  if (!finding) return;

  document.getElementById('modal-technique-id').textContent = techniqueId;
  document.getElementById('modal-technique-name').textContent = finding.technique_name;
  document.getElementById('modal-tactic').textContent = finding.tactic;
  
  const badgeEl = document.getElementById('modal-confidence');
  badgeEl.innerHTML = `<span class="badge ${getConfidenceClass(finding.confidence_score)}">${finding.confidence}</span>`;
  
  document.getElementById('modal-evidence-count').textContent = finding.evidence_count || 0;
  
  // Evidence list
  const evidenceList = document.getElementById('modal-evidence');
  if (finding.evidence && finding.evidence.length > 0) {
    evidenceList.innerHTML = finding.evidence.slice(0, 10).map(e => 
      `<li>${escapeHtml(e)}</li>`
    ).join('');
    
    if (finding.evidence.length > 10) {
      evidenceList.innerHTML += `<li style="color: var(--muted-color);">...and ${finding.evidence.length - 10} more</li>`;
    }
  } else {
    evidenceList.innerHTML = '<li>No evidence details available</li>';
  }
  
  // MITRE ATT&CK link
  document.getElementById('modal-attack-link').href = `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
  
  // Show modal
  document.getElementById('technique-modal').classList.add('active');
}

/**
 * Close technique modal
 */
function closeTechniqueModal() {
  document.getElementById('technique-modal').classList.remove('active');
}

/**
 * Handle keyboard navigation
 * @param {KeyboardEvent} e - Keyboard event
 */
function handleKeyboardNavigation(e) {
  // Escape key closes modal
  if (e.key === 'Escape') {
    const modal = document.getElementById('technique-modal');
    if (modal && modal.classList.contains('active')) {
      closeTechniqueModal();
    }
  }
  
  // Tab navigation for accessibility
  if (e.key === 'Tab') {
    // Let browser handle native tab navigation
  }
}

/**
 * Render tactics pie chart
 * @param {Array} findings - Findings data
 */
function renderTacticsChart(findings) {
  const canvas = document.getElementById('tactics-chart');
  if (!canvas) return;

  // Count by tactic
  const byTactic = {};
  findings.forEach(f => {
    const tactic = f.tactic || 'Unknown';
    byTactic[tactic] = (byTactic[tactic] || 0) + 1;
  });

  const labels = Object.keys(byTactic);
  const values = Object.values(byTactic);

  if (labels.length === 0) {
    canvas.style.display = 'none';
    return;
  }

  const isDark = getTheme() === 'dark';
  const colors = [
    'rgba(211, 47, 47, 0.8)',
    'rgba(255, 102, 0, 0.8)',
    'rgba(255, 170, 0, 0.8)',
    'rgba(76, 175, 80, 0.8)',
    'rgba(33, 150, 243, 0.8)',
    'rgba(156, 39, 176, 0.8)',
    'rgba(233, 30, 99, 0.8)',
    'rgba(0, 188, 212, 0.8)'
  ];

  if (tacticsChart) {
    tacticsChart.destroy();
    tacticsChart = null; // Nullify reference for garbage collection
  }

  tacticsChart = new Chart(canvas, {
    type: 'pie',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: colors,
        borderColor: isDark ? 'rgba(255,255,255,0.2)' : 'rgba(0,0,0,0.1)',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: isDark ? 'rgba(255,255,255,0.7)' : 'rgba(0,0,0,0.6)',
            boxWidth: 12
          }
        }
      }
    }
  });
}

/**
 * Load API calls with pagination
 * @param {boolean} reset - If true, reset to page 1 and clear existing data
 */
async function loadAPICalls(reset = false) {
  // Abort any in-flight request
  if (apiCallsAbortController) {
    apiCallsAbortController.abort();
  }
  apiCallsAbortController = new AbortController();
  const signal = apiCallsAbortController.signal;

  if (reset) {
    apiCallsPage = 1;
    apiCallsData = [];
    allAPICalls = [];
    formattedAPICallRows = []; // Clear pre-formatted cache
    document.getElementById('api-calls-table').innerHTML = 
      '<tr><td colspan="5" class="empty-state">Loading...</td></tr>';
  }

  try {
    const params = new URLSearchParams({
      page: String(apiCallsPage),
      per_page: String(apiCallsPerPage)
    });
    
    const apiName = document.getElementById('api-filter-name').value;
    const technique = document.getElementById('api-filter-technique').value;
    
    if (apiName) params.set('api_name', apiName);
    if (technique) params.set('technique_id', technique);

    const response = await fetch(`${API_BASE}/analyses/${sessionId}/api_calls?${params}`, { signal });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    const calls = data.items || [];
    
    apiCallsData = reset ? calls : [...apiCallsData, ...calls];
    allAPICalls = [...allAPICalls, ...calls];
    apiCallsTotalPages = data.pages || 1;
    
    renderAPICalls(apiCallsData);
    updatePaginationControls(data.page, data.pages);

  } catch (error) {
    if (error.name === 'AbortError') {
      // Request was aborted - don't show error, just return silently
      return;
    }
    console.error('Failed to load API calls:', error);
    document.getElementById('api-calls-table').innerHTML = 
      `<tr><td colspan="5" class="empty-state">Failed to load: ${escapeHtml(error.message)}</td></tr>`;
  }
}

/**
 * Update pagination controls (button visibility and page indicator)
 * @param {number} currentPage - Current page number
 * @param {number} totalPages - Total number of pages
 */
function updatePaginationControls(currentPage, totalPages) {
  const loadMoreBtn = document.getElementById('load-more-api');
  const pageInfoEl = document.getElementById('api-calls-page-info');
  
  if (loadMoreBtn) {
    loadMoreBtn.style.display = currentPage < totalPages ? 'inline-block' : 'none';
  }
  
  if (pageInfoEl) {
    pageInfoEl.textContent = `Page ${currentPage} of ${totalPages}`;
  }
}

/**
 * Format a single API call row with safe JSON handling
 * @param {Object} call - API call object
 * @returns {string} HTML row
 */
function formatAPICallRow(call) {
  const sequenceNum = call.sequence_number || '-';
  const techniqueId = call.technique_id || '-';
  const timestamp = call.timestamp ? new Date(call.timestamp).toLocaleTimeString() : '-';
  const apiName = escapeHtml(call.api_name || '-');
  const hasParams = !!call.params_json;
  
  // Pre-parse and format JSON safely with error handling
  let formattedJson = '';
  let buttonLabel = hasParams ? 'Show' : 'No params';
  
  if (hasParams) {
    try {
      // params_json may already be parsed (object) or a string
      const parsed = typeof call.params_json === 'string' ? JSON.parse(call.params_json) : call.params_json;
      formattedJson = escapeHtml(JSON.stringify(parsed, null, 2));
    } catch (e) {
      // Malformed JSON - display raw string with warning
      console.warn('Malformed params_json for call', sequenceNum, ':', e.message);
      formattedJson = escapeHtml('⚠️ Malformed JSON: ' + call.params_json);
      buttonLabel = 'Show (raw)';
    }
  }
  
  return `
    <tr>
      <td>${sequenceNum}</td>
      <td style="white-space: nowrap;">${timestamp}</td>
      <td>${apiName}</td>
      <td>
        <button class="btn btn-sm btn-outline" onclick="toggleJson('params-${sequenceNum}')" 
                style="font-size: 0.75rem; padding: 0.15rem 0.4rem;">
          ${buttonLabel}
        </button>
        <pre id="params-${sequenceNum}" class="json-viewer" style="display: none; margin-top: 0.5rem;">${formattedJson}</pre>
      </td>
      <td>${techniqueId !== '-' ? `<span class="badge">${escapeHtml(techniqueId)}</span>` : '-'}</td>
    </tr>
  `;
}

/**
 * Render API calls table
 * @param {Array} calls - API calls data
 */
function renderAPICalls(calls) {
  const tbody = document.getElementById('api-calls-table');
  
  if (calls.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No API calls recorded</td></tr>';
    return;
  }

  // Use pre-formatted rows if available (single-pass formatting)
  if (formattedAPICallRows.length === calls.length) {
    tbody.innerHTML = formattedAPICallRows.join('');
    return;
  }
  
  // First render - format all rows and cache them
  formattedAPICallRows = calls.map(formatAPICallRow);
  tbody.innerHTML = formattedAPICallRows.join('');
}

/**
 * Toggle JSON visibility
 * @param {string} elementId - Element ID
 */
function toggleJson(elementId) {
  const el = document.getElementById(elementId);
  if (el) {
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
  }
}

/**
 * Load more API calls - manages loading state to prevent double-clicks
 */
async function loadMoreAPICalls() {
  // Prevent rapid double-clicks
  if (isLoadingApiCalls) {
    return;
  }
  
  isLoadingApiCalls = true;
  const loadMoreBtn = document.getElementById('load-more-api');
  
  // Disable button and show loading state
  if (loadMoreBtn) {
    loadMoreBtn.disabled = true;
    loadMoreBtn.textContent = 'Loading...';
  }
  
  try {
    apiCallsPage++;
    await loadAPICalls();
  } finally {
    isLoadingApiCalls = false;
    
    // Re-enable button
    if (loadMoreBtn) {
      loadMoreBtn.disabled = false;
      loadMoreBtn.textContent = 'Load More';
    }
  }
}

/**
 * Apply API call filters
 */
function applyAPICallFilters() {
  loadAPICalls(true);
}

/**
 * Export API calls
 * @param {string} format - 'json' or 'csv'
 */
function exportAPICalls(format) {
  if (allAPICalls.length === 0) {
    showToast('No API calls to export', 'info');
    return;
  }

  if (format === 'json') {
    const json = JSON.stringify(allAPICalls, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    downloadBlob(blob, `api_calls_${sessionId}.json`);
    showToast('API calls exported as JSON', 'success');
    return;
  }

  if (format === 'csv') {
    // CSV escape: wrap in quotes if contains comma, newline, carriage return, or quote
    // Double any internal quotes per RFC 4180
    function csvEscape(value) {
      if (value === null || value === undefined) {
        return '';
      }
      const str = String(value);
      const needsQuotes = /[",\r\n]/.test(str);
      const escaped = str.replace(/"/g, '""');
      return needsQuotes ? `"${escaped}"` : escaped;
    }

    // Headers
    const headers = [
      'sequence_number',
      'timestamp',
      'api_name',
      'syscall_name',
      'params_json',
      'return_value',
      'technique_id',
      'confidence'
    ];

    // Build CSV rows
    const rows = allAPICalls.map(call => [
      call.sequence_number ?? '',
      call.timestamp ?? '',  // Already ISO format from API
      call.api_name ?? '',
      call.syscall_name ?? '',
      call.params_json ?? '',
      call.return_value ?? '',
      call.technique_id ?? '',
      call.confidence ?? ''
    ].map(csvEscape).join(','));

    // Prepend UTF-8 BOM for Excel compatibility
    const BOM = '\uFEFF';
    const csvContent = BOM + [headers.join(','), ...rows].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' });
    downloadBlob(blob, `api_calls_${sessionId}.csv`);
    showToast('API calls exported as CSV', 'success');
    return;
  }

  showToast('Unknown export format: ' + format, 'error');
}

/**
 * Download blob
 * @param {Blob} blob - Blob to download
 * @param {string} filename - Filename
 */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Load reports and preview
 * Handles 404 gracefully, sanitizes markdown, shows loading state, disables links until ready
 */
async function loadReports() {
  const previewEl = document.getElementById('report-preview');
  if (!previewEl) return;
  
  // Check marked.js availability
  if (typeof marked === 'undefined') {
    previewEl.innerHTML = '<p class="empty-state">Markdown preview unavailable (marked.js not loaded)</p>';
    return;
  }
  
  try {
    const response = await fetch(`${API_BASE}/reports/${sessionId}/report`);
    
    // Handle 404 gracefully - report not ready yet
    if (response.status === 404) {
      previewEl.innerHTML = '<p class="empty-state">Report not yet available</p>';
      return;
    }
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const markdown = await response.text();
    const html = marked.parse(markdown);
    previewEl.innerHTML = sanitizeHtml(html);
    
    // Update download links
    document.getElementById('download-navigator').href = `${API_BASE}/reports/${sessionId}/navigator`;
    document.getElementById('download-stix').href = `${API_BASE}/reports/${sessionId}/stix`;
    document.getElementById('download-markdown').href = `${API_BASE}/reports/${sessionId}/report`;
    document.getElementById('download-json').href = `${API_BASE}/reports/${sessionId}/log`;
    
  } catch (error) {
    console.error('Failed to load reports:', error);
    previewEl.innerHTML = `<p class="empty-state">Failed to load report: ${escapeHtml(error.message)}</p>`;
  }
}

/**
 * Simple HTML sanitization - strip dangerous tags and attributes
 * @param {string} html - HTML string to sanitize
 * @returns {string} Sanitized HTML
 */
function sanitizeHtml(html) {
  // Dangerous attributes that can execute JavaScript
  const dangerousAttrs = [
    'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover',
    'onmousemove', 'onmouseout', 'onmouseenter', 'onmouseleave',
    'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onerror',
    'onsubmit', 'onreset', 'onfocus', 'onblur', 'onchange',
    'oninput', 'onscroll', 'onresize', 'onunload', 'onbeforeunload',
    'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover',
    'ondragstart', 'ondrop', 'oncontextmenu', 'onwheel', 'oncopy',
    'oncut', 'onpaste', 'onabort', 'oncanplay', 'oncanplaythrough',
    'oncuechange', 'ondurationchange', 'onemptied', 'onended',
    'onloadeddata', 'onloadedmetadata', 'onloadstart', 'onpause',
    'onplay', 'onplaying', 'onprogress', 'onratechange', 'onseeked',
    'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate',
    'onvolumechange', 'onwaiting', 'ontouchstart', 'ontouchmove',
    'ontouchend', 'ontouchcancel', 'onpointerdown', 'onpointerup',
    'onpointermove', 'onpointerenter', 'onpointerleave', 'onpointercancel',
    'ongotpointercapture', 'onlostpointercapture', 'onanimationstart',
    'onanimationend', 'onanimationiteration', 'ontransitionend',
    'onmessage', 'onopen', 'onclose', 'onstorage', 'onpopstate',
    'onhashchange', 'onpageshow', 'onpagehide', 'onoffline', 'ononline',
    'onshow', 'ontoggle', 'oninvalid', 'onsearch', 'onselect',
    // Style can contain expression() or url(javascript:...)
    'style',
    // Source attributes that can load malicious content
    'src', 'srcdoc', 'data', 'formaction', 'action', 'poster', 'background',
    'dynsrc', 'lowsrc'
  ];
  
  // Remove dangerous tags entirely
  const dangerousTags = ['script', 'iframe', 'object', 'embed', 'applet', 'form', 'input', 'button', 'textarea', 'select', 'link', 'meta', 'base'];
  let sanitized = html;
  
  dangerousTags.forEach(tag => {
    // Remove opening tags with attributes
    const openTagRegex = new RegExp(`<${tag}(\\s[^>]*)?>`, 'gi');
    sanitized = sanitized.replace(openTagRegex, '');
    // Remove closing tags
    const closeTagRegex = new RegExp(`</${tag}>`, 'gi');
    sanitized = sanitized.replace(closeTagRegex, '');
  });
  
  // Remove dangerous attributes
  dangerousAttrs.forEach(attr => {
    // Match attribute with various quote styles: attr="value", attr='value', attr=value
    const attrRegex = new RegExp(`\\s${attr}\\s*=\\s*(?:"[^"]*"|'[^']*'|[^\\s>]*)`, 'gi');
    sanitized = sanitized.replace(attrRegex, '');
  });
  
  // Check for javascript: in href attributes (case-insensitive, handles whitespace tricks)
  // Remove any whitespace within the protocol check
  const hrefRegex = /href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*))/gi;
  sanitized = sanitized.replace(hrefRegex, (match, doubleQuoted, singleQuoted, unquoted) => {
    const value = (doubleQuoted || singleQuoted || unquoted || '').trim();
    // Remove all whitespace and check for javascript: protocol (case-insensitive)
    const normalizedValue = value.replace(/\s+/g, '').toLowerCase();
    if (normalizedValue.startsWith('javascript:')) {
      return '';
    }
    return match;
  });
  
  // Check for data: URLs in src attributes that could contain scripts
  const srcRegex = /src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*))/gi;
  sanitized = sanitized.replace(srcRegex, (match, doubleQuoted, singleQuoted, unquoted) => {
    const value = (doubleQuoted || singleQuoted || unquoted || '').trim();
    const normalizedValue = value.replace(/\s+/g, '').toLowerCase();
    if (normalizedValue.startsWith('data:') && (normalizedValue.includes('script') || normalizedValue.includes('html'))) {
      return '';
    }
    return match;
  });
  
  return sanitized;
}

/**
 * Start polling for status updates
 */
function startPolling() {
  const indicator = document.getElementById('polling-indicator');
  
  // Show polling indicator
  if (indicator) {
    indicator.style.display = 'block';
    indicator.textContent = 'Polling...';
    indicator.style.color = '';
  }
  
  pollInterval = setInterval(async () => {
    // Guard: prevent concurrent polling requests
    if (isPolling) {
      return;
    }
    
    // Check max attempts
    if (pollAttempts >= MAX_POLL_ATTEMPTS) {
      stopPolling();
      showToast('Polling timed out after 10 minutes', 'error');
      return;
    }
    
    isPolling = true;
    pollAttempts++;
    
    // Abort any in-flight polling request
    if (pollingAbortController) {
      pollingAbortController.abort();
    }
    pollingAbortController = new AbortController();
    const signal = pollingAbortController.signal;
    
    try {
      const response = await fetch(`${API_BASE}/analyze/${sessionId}`, { signal });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      consecutiveFailures = 0; // Reset on success
      
      // Update indicator with attempt count
      if (indicator) {
        indicator.textContent = `Polling... (${pollAttempts}/${MAX_POLL_ATTEMPTS})`;
      }
      
      // Check if analysis completed
      if (data.status === 'completed' || data.status === 'failed') {
        stopPolling();
        showToast(`Analysis ${data.status}`, data.status === 'completed' ? 'success' : 'error');
        // Reload page after short delay to show results
        setTimeout(() => {
          window.location.reload();
        }, 1500);
        return;
      }
      
      // Update analysis data
      analysisData = data;
      
    } catch (error) {
      if (error.name === 'AbortError') {
        // Request was aborted - don't count as failure
        return;
      }
      
      console.error('Poll failed:', error);
      consecutiveFailures++;
      
      // Update indicator with error state
      if (indicator) {
        indicator.textContent = `Poll error (${consecutiveFailures}/${MAX_CONSECUTIVE_FAILURES})`;
        indicator.style.color = '#d32f2f';
      }
      
      // Show toast after 3 consecutive failures
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        showToast('Polling failed multiple times. Refresh page to retry.', 'error');
      }
      
      // Stop if we've exceeded max attempts
      if (pollAttempts >= MAX_POLL_ATTEMPTS) {
        stopPolling();
        showToast('Polling timed out after 10 minutes', 'error');
      }
    } finally {
      isPolling = false;
    }
  }, 5000);
}

/**
 * Stop polling
 */
function stopPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  
  // Abort in-flight polling request
  if (pollingAbortController) {
    pollingAbortController.abort();
    pollingAbortController = null;
  }
  
  const indicator = document.getElementById('polling-indicator');
  if (indicator) {
    indicator.style.display = 'none';
    indicator.textContent = '';
    indicator.style.color = '';
  }
  
  isPolling = false;
  consecutiveFailures = 0;
}

/**
 * Cleanup function called on page unload
 */
function cleanup() {
  stopPolling();
  
  // Abort any in-flight API calls request
  if (apiCallsAbortController) {
    apiCallsAbortController.abort();
    apiCallsAbortController = null;
  }
  
  // Abort any in-flight polling request (redundant with stopPolling but explicit)
  if (pollingAbortController) {
    pollingAbortController.abort();
    pollingAbortController = null;
  }
  
  // Nullify chart reference to allow garbage collection
  if (tacticsChart) {
    tacticsChart.destroy();
    tacticsChart = null;
  }
  
  // Clear cached data
  formattedAPICallRows = [];
  allAPICalls = [];
  apiCallsData = [];
  isLoadingApiCalls = false;
}

// Register cleanup on page unload to prevent memory leaks
window.addEventListener('beforeunload', cleanup);

/**
 * Switch tab
 * @param {string} tabId - Tab ID
 */
function switchTab(tabId) {
  // Update buttons
  document.querySelectorAll('.tab-button').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  
  // Update content
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.toggle('active', content.id === `tab-${tabId}`);
  });
  
  // Update URL hash
  window.location.hash = tabId;
}

/**
 * Handle tab clicks
 */
function initTabs() {
  const tabs = document.getElementById('tabs');
  
  tabs.addEventListener('click', (e) => {
    if (e.target.classList.contains('tab-button')) {
      switchTab(e.target.dataset.tab);
    }
  });
  
  // Restore from hash
  const hash = window.location.hash.slice(1);
  if (hash && ['overview', 'techniques', 'api-calls', 'reports'].includes(hash)) {
    switchTab(hash);
  }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initTabs();
  loadAnalysisDetail();
});

// Keyboard navigation
document.addEventListener('keydown', handleKeyboardNavigation);

// Make functions globally available
window.showTechniqueModal = showTechniqueModal;
window.closeTechniqueModal = closeTechniqueModal;
window.toggleJson = toggleJson;
window.loadMoreAPICalls = loadMoreAPICalls;
window.applyAPICallFilters = applyAPICallFilters;
window.exportAPICalls = exportAPICalls;
