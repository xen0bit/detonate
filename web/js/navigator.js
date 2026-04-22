/**
 * ATT&CK Navigator - Full matrix visualization
 * 
 * Dependencies (must be loaded before this file):
 * - app.js (provides API_BASE, escapeHtml, formatAbsoluteTime, initTheme, showToast)
 */

// ============================================================================
// DEPENDENCY CHECK - Fail fast if required globals are missing
// ============================================================================
(function validateDependencies() {
  const required = ['API_BASE', 'escapeHtml', 'formatAbsoluteTime', 'initTheme', 'showToast'];
  const missing = required.filter(name => typeof window[name] === 'undefined');
  
  if (missing.length > 0) {
    throw new Error(`navigator.js requires: ${missing.join(', ')}. Ensure app.js is loaded first.`);
  }
})();

// ============================================================================
// STATE
// ============================================================================
let sessionId = null;
let allTechniques = [];
let filteredTechniques = [];

// Event listener references for cleanup
let searchListener = null;
let confidenceListener = null;

// AbortController for evidence fetch (prevents memory leaks and race conditions)
let evidenceAbortController = null;

// DOM element references (validated at init)
let gridEl = null;
let searchInput = null;
let confidenceFilter = null;
let statsEl = null;

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * Initialize DOM references with null-safe access
 * @returns {boolean} True if all required elements found
 */
function initDOMReferences() {
  gridEl = document.getElementById('navigator-grid');
  searchInput = document.getElementById('navigator-search');
  confidenceFilter = document.getElementById('navigator-confidence');
  statsEl = document.getElementById('navigator-stats');
  
  const missing = [];
  if (!gridEl) missing.push('navigator-grid');
  if (!searchInput) missing.push('navigator-search');
  if (!confidenceFilter) missing.push('navigator-confidence');
  if (!statsEl) missing.push('navigator-stats');
  
  if (missing.length > 0) {
    console.error(`navigator.js: Missing DOM elements: ${missing.join(', ')}`);
    return false;
  }
  
  return true;
}

/**
 * Attach event listeners with cleanup support
 */
function attachEventListeners() {
  // Debounced search
  let searchTimeout = null;
  searchListener = () => {
    if (searchTimeout) clearTimeout(searchTimeout);
    searchTimeout = setTimeout(applyFilters, 300);
  };
  searchInput.addEventListener('input', searchListener);
  
  // Confidence filter
  confidenceListener = () => applyFilters();
  confidenceFilter.addEventListener('change', confidenceListener);
  
  // Modal close handlers
  const closeBtn = document.getElementById('modal-close-btn');
  const modal = document.getElementById('technique-modal');
  
  if (closeBtn) {
    closeBtn.addEventListener('click', closeTechniqueModal);
  }
  
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeTechniqueModal();
    });
  }
  
  // Keyboard escape to close modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal && modal.classList.contains('active')) {
      closeTechniqueModal();
    }
  });
}

/**
 * Cleanup function for page navigation (prevents memory leaks)
 */
function cleanup() {
  if (searchListener && searchInput) {
    searchInput.removeEventListener('input', searchListener);
  }
  if (confidenceListener && confidenceFilter) {
    confidenceFilter.removeEventListener('change', confidenceListener);
  }
  // Abort any in-flight evidence fetch
  if (evidenceAbortController) {
    evidenceAbortController.abort();
    evidenceAbortController = null;
  }
}

// Cleanup on page unload
window.addEventListener('beforeunload', cleanup);

// ============================================================================
// CORE FUNCTIONS
// ============================================================================

/**
 * Get session ID from URL
 * @returns {string|null} Session ID or null
 */
function getSessionId() {
  const params = new URLSearchParams(window.location.search);
  return params.get('id');
}

/**
 * Load navigator data from API
 */
async function loadNavigatorData() {
  sessionId = getSessionId();
  
  if (!sessionId) {
    showError('No analysis ID provided in URL');
    return;
  }

  // Set back link and subtitle
  const backLink = document.getElementById('back-to-analysis');
  const subtitle = document.getElementById('navigator-subtitle');
  
  if (backLink) {
    backLink.href = `/web/analysis.html?id=${sessionId}`;
  }
  if (subtitle) {
    subtitle.textContent = `Analysis: ${sessionId.substring(0, 8)}...`;
  }

  try {
    const response = await fetch(`${API_BASE}/analyses/${sessionId}/findings?page=1&per_page=1000`);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    allTechniques = data.items || [];
    filteredTechniques = [...allTechniques];

    renderStatistics();
    renderMatrix(filteredTechniques);

  } catch (error) {
    console.error('Failed to load navigator data:', error);
    showError(`Failed to load ATT&CK matrix: ${error.message}`);
  }
}

/**
 * Show error message in grid
 * @param {string} message - Error message to display
 */
function showError(message) {
  if (!gridEl) {
    console.error('Cannot show error: grid element not found');
    return;
  }
  
  gridEl.innerHTML = `
    <article style="grid-column: 1 / -1; border-left: 4px solid #d32f2f;">
      <h3>Error</h3>
      <p>${escapeHtml(message)}</p>
      <a href="/web/analyses.html" class="btn btn-outline" style="margin-top: 1rem;">Back to Analyses</a>
    </article>
  `;
}

/**
 * Render statistics cards
 */
function renderStatistics() {
  const total = allTechniques.length;
  const high = allTechniques.filter(t => t.confidence_score >= 0.7).length;
  const medium = allTechniques.filter(t => t.confidence_score >= 0.4 && t.confidence_score < 0.7).length;
  const low = allTechniques.filter(t => t.confidence_score < 0.4).length;

  const mappings = [
    { id: 'stat-total-techs', value: total },
    { id: 'stat-high', value: high },
    { id: 'stat-medium', value: medium },
    { id: 'stat-low', value: low }
  ];

  mappings.forEach(({ id, value }) => {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = value;
    }
  });
}

/**
 * Render the full ATT&CK matrix using document fragment for efficiency
 * @param {Array} techniques - Techniques to render
 */
function renderMatrix(techniques) {
  if (!gridEl) return;
  
  if (techniques.length === 0) {
    gridEl.innerHTML = '<p class="empty-state" style="grid-column: 1 / -1;">No techniques match the current filters</p>';
    return;
  }

  // Group by tactic
  const byTactic = {};
  techniques.forEach(t => {
    const tactic = t.tactic || 'Unknown';
    if (!byTactic[tactic]) {
      byTactic[tactic] = [];
    }
    byTactic[tactic].push(t);
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

  // Use document fragment for efficient DOM insertion
  const fragment = document.createDocumentFragment();
  gridEl.innerHTML = '';

  sortedTactics.forEach(tactic => {
    const techs = byTactic[tactic].sort((a, b) => a.technique_id.localeCompare(b.technique_id));
    
    const columnEl = document.createElement('div');
    columnEl.className = 'navigator-tactic';
    
    const headingEl = document.createElement('h3');
    headingEl.textContent = `${tactic} (${techs.length})`;
    columnEl.appendChild(headingEl);
    
    techs.forEach(t => {
      const techniqueEl = document.createElement('div');
      techniqueEl.className = `navigator-technique ${getConfidenceClass(t.confidence_score)}`;
      techniqueEl.setAttribute('data-technique-id', t.technique_id);
      techniqueEl.setAttribute('tabindex', '0');
      techniqueEl.title = `${t.technique_name} (${t.confidence})`;
      
      const idSpan = document.createElement('span');
      idSpan.className = 'tech-id';
      idSpan.textContent = t.technique_id;
      
      const nameSpan = document.createElement('span');
      nameSpan.className = 'tech-name';
      nameSpan.textContent = t.technique_name;
      
      techniqueEl.appendChild(idSpan);
      techniqueEl.appendChild(nameSpan);
      
      // Click handler
      techniqueEl.addEventListener('click', () => showTechniqueModal(t.technique_id));
      
      // Keyboard handler for accessibility
      techniqueEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          showTechniqueModal(t.technique_id);
        }
      });
      
      columnEl.appendChild(techniqueEl);
    });
    
    fragment.appendChild(columnEl);
  });

  gridEl.appendChild(fragment);
}

/**
 * Get confidence CSS class based on score
 * @param {number} score - Confidence score (0-1)
 * @returns {string} CSS class name
 */
function getConfidenceClass(score) {
  if (score >= 0.7) return 'high';
  if (score >= 0.4) return 'medium';
  return 'low';
}

/**
 * Apply search and filter criteria
 */
function applyFilters() {
  const searchTerm = searchInput.value.toLowerCase().trim();
  const minConfidence = parseFloat(confidenceFilter.value) || 0;

  filteredTechniques = allTechniques.filter(t => {
    // Confidence filter
    if (t.confidence_score < minConfidence) return false;
    
    // Search filter
    if (searchTerm) {
      const searchMatch = 
        t.technique_id.toLowerCase().includes(searchTerm) ||
        t.technique_name.toLowerCase().includes(searchTerm) ||
        (t.tactic && t.tactic.toLowerCase().includes(searchTerm));
      
      if (!searchMatch) return false;
    }
    
    return true;
  });

  renderStatistics();
  renderMatrix(filteredTechniques);
}

/**
 * Show technique details in modal
 * @param {string} techniqueId - Technique ID to display
 */
async function showTechniqueModal(techniqueId) {
  const technique = allTechniques.find(t => t.technique_id === techniqueId);
  if (!technique) return;

  // Safe text content assignments
  setTextContentSafe('modal-technique-id', techniqueId);
  setTextContentSafe('modal-technique-name', technique.technique_name);
  setTextContentSafe('modal-tactic', technique.tactic || 'Unknown');
  setTextContentSafe('modal-evidence-count', String(technique.evidence_count || 0));
  setTextContentSafe('modal-first-seen', technique.first_seen ? formatAbsoluteTime(technique.first_seen) : 'N/A');
  setTextContentSafe('modal-last-seen', technique.last_seen ? formatAbsoluteTime(technique.last_seen) : 'N/A');
  
  // Confidence badge
  const badgeEl = document.getElementById('modal-confidence');
  if (badgeEl) {
    badgeEl.innerHTML = `<span class="badge ${getConfidenceClass(technique.confidence_score)}">${escapeHtml(technique.confidence)}</span>`;
  }

  // Load detailed evidence from API calls
  await loadEvidenceForTechnique(techniqueId);

  // MITRE ATT&CK link
  const linkEl = document.getElementById('modal-attack-link');
  if (linkEl) {
    linkEl.href = `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
  }

  // Show modal
  const modal = document.getElementById('technique-modal');
  if (modal) {
    modal.classList.add('active');
  }
}

/**
 * Load and display evidence API calls for a technique
 * @param {string} techniqueId - Technique ID
 */
async function loadEvidenceForTechnique(techniqueId) {
  // Abort any previous in-flight request to prevent race conditions
  if (evidenceAbortController) {
    evidenceAbortController.abort();
  }
  
  // Create new AbortController for this request
  evidenceAbortController = new AbortController();
  const { signal } = evidenceAbortController;
  
  const modal = document.getElementById('technique-modal');
  const evidenceContainer = document.getElementById('modal-evidence');
  
  if (!evidenceContainer) return;
  
  // Show loading state
  evidenceContainer.innerHTML = '<p>Loading evidence...</p>';
  
  try {
    const response = await fetch(`${API_BASE}/analyses/${sessionId}/api_calls?page=1&per_page=100&technique_id=${encodeURIComponent(techniqueId)}`, {
      signal: signal
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const data = await response.json();
    const apiCalls = data.items || [];
    
    // Check if modal is still active and this is still the current technique
    // (user might have closed and reopened with different technique)
    if (!modal || !modal.classList.contains('active')) {
      return; // Modal closed, skip DOM update
    }
    
    if (apiCalls.length === 0) {
      evidenceContainer.innerHTML = '<p class="empty-state">No API call evidence found</p>';
      return;
    }
    
    // Render evidence list
    const fragment = document.createDocumentFragment();
    const listEl = document.createElement('ul');
    listEl.style.cssText = 'list-style: none; padding: 0; margin: 0;';
    
    apiCalls.slice(0, 10).forEach((call, idx) => {
      const li = document.createElement('li');
      li.style.cssText = 'padding: 0.5rem; border-bottom: 1px solid var(--muted-border-color); font-size: 0.85rem;';
      
      const seq = call.sequence_number || idx + 1;
      const apiName = escapeHtml(call.api_name || 'Unknown');
      const timestamp = call.timestamp ? formatAbsoluteTime(call.timestamp) : 'N/A';
      
      li.innerHTML = `<strong>${escapeHtml(apiName)}</strong> <span style="color: var(--muted-color);">(${timestamp})</span>`;
      fragment.appendChild(li);
    });
    
    listEl.appendChild(fragment);
    evidenceContainer.innerHTML = '';
    evidenceContainer.appendChild(listEl);
    
    if (apiCalls.length > 10) {
      const moreEl = document.createElement('p');
      moreEl.style.cssText = 'font-size: 0.8rem; color: var(--muted-color); margin-top: 0.5rem;';
      moreEl.textContent = `...and ${apiCalls.length - 10} more API calls`;
      evidenceContainer.appendChild(moreEl);
    }
    
  } catch (error) {
    if (error.name === 'AbortError') {
      // Request was aborted, don't update DOM
      return;
    }
    
    console.error('Failed to load evidence:', error);
    if (modal && modal.classList.contains('active')) {
      evidenceContainer.innerHTML = `<p style="color: #d32f2f;">Failed to load evidence: ${escapeHtml(error.message)}</p>`;
    }
  }
}

/**
 * Close the technique modal and abort any in-flight evidence fetch
 */
function closeTechniqueModal() {
  // Abort evidence fetch to prevent memory leaks and race conditions
  if (evidenceAbortController) {
    evidenceAbortController.abort();
    evidenceAbortController = null;
  }
  
  const modal = document.getElementById('technique-modal');
  if (modal) {
    modal.classList.remove('active');
  }
}

/**
 * Export navigator layer as JSON file
 */
function exportLayer() {
  if (allTechniques.length === 0) {
    showToast('No techniques to export', 'info');
    return;
  }

  const layer = {
    name: `Detonate Analysis - ${sessionId}`,
    versions: {
      attack: '14',
      navigator: '4.8.2',
      layer: '4.4'
    },
    domain: 'enterprise-attack',
    description: 'MITRE ATT&CK techniques detected by Detonate malware analysis',
    filters: {
      platforms: ['Windows', 'Linux', 'macOS']
    },
    sorting: 0,
    layout: {
      layout: 'side',
      aggregateFunction: 'average',
      showID: true,
      showName: true
    },
    hideDisabled: false,
    techniques: allTechniques.map(t => ({
      techniqueID: t.technique_id,
      tactic: t.tactic,
      color: getTechniqueColor(t.confidence_score),
      comment: `Confidence: ${t.confidence}\nEvidence: ${t.evidence_count} items`,
      enabled: true,
      metadata: [
        { name: 'Confidence', value: t.confidence },
        { name: 'Evidence Count', value: String(t.evidence_count) }
      ]
    })),
    gradient: {
      colors: ['#ffaa00', '#ff6600', '#d32f2f'],
      minValue: 0,
      maxValue: 1
    },
    legendItems: [
      { color: '#ffaa00', label: 'Low Confidence' },
      { color: '#ff6600', label: 'Medium Confidence' },
      { color: '#d32f2f', label: 'High Confidence' }
    ],
    showTactics: true,
    searchEnabled: true,
    selectEnabled: true
  };

  const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `navigator_layer_${sessionId}.json`);
  showToast('Navigator layer exported', 'success');
}

/**
 * Get color hex for technique based on confidence
 * @param {number} score - Confidence score
 * @returns {string} Hex color
 */
function getTechniqueColor(score) {
  if (score >= 0.7) return '#d32f2f';
  if (score >= 0.4) return '#ff6600';
  return '#ffaa00';
}

/**
 * Download a blob as a file
 * @param {Blob} blob - Blob to download
 * @param {string} filename - Filename for download
 */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Safely set text content on an element by ID
 * @param {string} elementId - Element ID
 * @param {string} text - Text to set
 */
function setTextContentSafe(elementId, text) {
  const el = document.getElementById(elementId);
  if (el) {
    el.textContent = text;
  }
}

// ============================================================================
// PAGE LOAD INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Validate DOM structure
  if (!initDOMReferences()) {
    showError('Page structure invalid. Check HTML elements.');
    return;
  }
  
  // Initialize theme from app.js
  initTheme();
  
  // Attach event listeners
  attachEventListeners();
  
  // Load data
  loadNavigatorData();
});

// Export functions to global scope for HTML onclick handlers
window.showTechniqueModal = showTechniqueModal;
window.closeTechniqueModal = closeTechniqueModal;
window.applyFilters = applyFilters;
window.exportLayer = exportLayer;
