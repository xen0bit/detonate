/**
 * Analyses List Page - Browse, filter, paginate, and delete analyses
 */

// State
let currentPage = 1;
let currentFilters = {};
let selectedAnalyses = new Set();
let totalPages = 1;
const perPage = 20;

// DOM Elements
const filterForm = document.getElementById('filter-form');
const clearFiltersBtn = document.getElementById('clear-filters');
const analysesTable = document.getElementById('analyses-table');
const pagination = document.getElementById('pagination');
const pageInfo = document.getElementById('page-info');
const prevPageBtn = document.getElementById('prev-page');
const nextPageBtn = document.getElementById('next-page');
const selectAllCheckbox = document.getElementById('select-all');
const bulkActions = document.getElementById('bulk-actions');
const selectedCount = document.getElementById('selected-count');
const bulkDeleteBtn = document.getElementById('bulk-delete');
const bulkCancelBtn = document.getElementById('bulk-cancel');

/**
 * Parse query parameters from URL
 * @returns {Object} Query params
 */
function parseQueryParams() {
  const params = new URLSearchParams(window.location.search);
  return {
    page: parseInt(params.get('page') || '1', 10),
    status: params.get('status') || '',
    platform: params.get('platform') || '',
    search: params.get('search') || ''
  };
}

/**
 * Update URL query params without reloading
 * @param {Object} params - New params
 */
function updateQueryParams(params) {
  const url = new URL(window.location);
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === '') {
      url.searchParams.delete(key);
    } else {
      url.searchParams.set(key, value);
    }
  }
  window.history.replaceState({}, '', url);
}

/**
 * Load analyses with current filters and pagination
 */
async function loadAnalyses() {
  const params = parseQueryParams();
  currentPage = params.page || 1;
  currentFilters = {
    status: params.status,
    platform: params.platform,
    search: params.search
  };

  // Update form to match URL params
  document.getElementById('filter-status').value = currentFilters.status;
  document.getElementById('filter-platform').value = currentFilters.platform;
  document.getElementById('filter-search').value = currentFilters.search;

  // Set loading state
  analysesTable.innerHTML = '<tr><td colspan="9" class="empty-state">Loading...</td></tr>';
  bulkActions.style.display = 'none';
  selectedAnalyses.clear();
  selectAllCheckbox.checked = false;

  try {
    // Build query string
    const queryParams = new URLSearchParams();
    queryParams.set('page', String(currentPage));
    queryParams.set('per_page', String(perPage));
    if (currentFilters.status) queryParams.set('status', currentFilters.status);
    if (currentFilters.platform) queryParams.set('platform', currentFilters.platform);
    if (currentFilters.search) queryParams.set('search', currentFilters.search);

    const response = await fetch(`${API_BASE}/reports?${queryParams}`);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    const analyses = data.items || data.analyses || [];
    totalPages = data.pages || 1;

    if (analyses.length === 0) {
      analysesTable.innerHTML = '<tr><td colspan="9" class="empty-state">No analyses found. <a href="/web/submit.html">Submit one?</a></td></tr>';
      pagination.style.display = 'none';
      return;
    }

    // Render table
    renderTable(analyses);
    renderPagination();

  } catch (error) {
    console.error('Failed to load analyses:', error);
    analysesTable.innerHTML = `<tr><td colspan="9" class="empty-state">Failed to load: ${escapeHtml(error.message)}</td></tr>`;
    pagination.style.display = 'none';
  }
}

/**
 * Render analyses table
 * @param {Array} analyses - Analyses data
 */
function renderTable(analyses) {
  const rows = analyses.map(analysis => {
    const sessionId = analysis.session_id || 'N/A';
    // Backend returns sample_sha256, not sha256
    const sha256 = escapeHtml(analysis.sample_sha256 || analysis.sha256 || 'N/A');
    const platform = escapeHtml(analysis.platform || 'N/A');
    const status = escapeHtml(analysis.status || 'unknown');
    // Backend doesn't return filename or techniques_count in list endpoint
    const filename = escapeHtml(analysis.filename || analysis.sample_filename || 'unknown');
    const techniques = escapeHtml(String(analysis.techniques_count ?? analysis.techniques ?? 0));
    const createdAt = analysis.created_at ? formatAbsoluteTime(analysis.created_at) : 'N/A';
    const isSelected = selectedAnalyses.has(sessionId);

    return `
      <tr>
        <td>
          <input type="checkbox" class="analysis-checkbox" data-session-id="${escapeHtml(sessionId)}" ${isSelected ? 'checked' : ''}>
        </td>
        <td>
          <a href="/web/analysis.html?id=${escapeHtml(sessionId)}" class="truncate" title="${escapeHtml(sessionId)}">
            ${escapeHtml(sessionId.substring(0, 8))}
          </a>
        </td>
        <td class="truncate" title="${filename}" style="max-width: 200px;">${filename}</td>
        <td class="truncate" title="${sha256}" style="max-width: 150px;">
          ${sha256.substring(0, 16)}...
          <button class="btn copy-btn btn-outline" onclick="copyHash('${escapeHtml(sha256)}')" title="Copy SHA256">
            📋
          </button>
        </td>
        <td>${platform}</td>
        <td><span class="badge ${status}">${status}</span></td>
        <td>${techniques}</td>
        <td style="white-space: nowrap;">${createdAt}</td>
        <td>
          <a href="/web/analysis.html?id=${escapeHtml(sessionId)}" class="btn btn-sm btn-outline" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">
            View
          </a>
          <button class="btn btn-sm btn-outline" onclick="deleteAnalysis('${escapeHtml(sessionId)}', '${filename}')" 
                  style="padding: 0.25rem 0.5rem; font-size: 0.75rem; color: #d32f2f; border-color: #d32f2f; margin-left: 0.25rem;">
            Delete
          </button>
        </td>
      </tr>
    `;
  }).join('');

  analysesTable.innerHTML = rows;

  // Add checkbox listeners
  document.querySelectorAll('.analysis-checkbox').forEach(checkbox => {
    checkbox.addEventListener('change', handleCheckboxChange);
  });
}

/**
 * Render pagination controls
 */
function renderPagination() {
  if (totalPages <= 1) {
    pagination.style.display = 'none';
    return;
  }

  pagination.style.display = 'flex';
  pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
  prevPageBtn.disabled = currentPage <= 1;
  nextPageBtn.disabled = currentPage >= totalPages;
}

/**
 * Handle checkbox change for bulk selection
 * @param {Event} e - Change event
 */
function handleCheckboxChange(e) {
  const sessionId = e.target.dataset.sessionId;
  
  if (e.target.checked) {
    selectedAnalyses.add(sessionId);
  } else {
    selectedAnalyses.delete(sessionId);
  }

  updateBulkActions();
}

/**
 * Handle select all checkbox
 */
function handleSelectAll() {
  const checkboxes = document.querySelectorAll('.analysis-checkbox');
  const selectAll = selectAllCheckbox.checked;

  checkboxes.forEach(checkbox => {
    checkbox.checked = selectAll;
    const sessionId = checkbox.dataset.sessionId;
    if (selectAll) {
      selectedAnalyses.add(sessionId);
    } else {
      selectedAnalyses.delete(sessionId);
    }
  });

  updateBulkActions();
}

/**
 * Update bulk actions UI
 */
function updateBulkActions() {
  const count = selectedAnalyses.size;
  selectedCount.textContent = count;
  
  if (count > 0) {
    bulkActions.style.display = 'block';
  } else {
    bulkActions.style.display = 'none';
  }
}

/**
 * Delete a single analysis
 * @param {string} sessionId - Session ID to delete
 * @param {string} filename - Filename for confirmation
 */
async function deleteAnalysis(sessionId, filename) {
  if (!confirm(`Are you sure you want to delete "${filename}"? This cannot be undone.`)) {
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/reports/${sessionId}`, {
      method: 'DELETE'
    });

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Analysis not found');
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    showToast('Analysis deleted successfully', 'success');
    loadAnalyses(); // Reload table

  } catch (error) {
    console.error('Failed to delete analysis:', error);
    showToast('Failed to delete: ' + error.message, 'error');
  }
}

/**
 * Delete selected analyses in bulk
 */
async function bulkDelete() {
  const count = selectedAnalyses.size;
  if (count === 0) return;

  if (!confirm(`Are you sure you want to delete ${count} analyses? This cannot be undone.`)) {
    return;
  }

  let successCount = 0;
  let failCount = 0;

  for (const sessionId of selectedAnalyses) {
    try {
      const response = await fetch(`${API_BASE}/reports/${sessionId}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        successCount++;
      } else {
        failCount++;
      }
    } catch (error) {
      console.error('Failed to delete', sessionId, error);
      failCount++;
    }
  }

  showToast(`Deleted ${successCount} analyses. ${failCount > 0 ? `${failCount} failed.` : ''}`, successCount > 0 ? 'success' : 'error');
  
  selectedAnalyses.clear();
  updateBulkActions();
  loadAnalyses();
}

/**
 * Copy hash to clipboard
 * @param {string} hash - Hash to copy
 */
async function copyHash(hash) {
  const success = await copyToClipboard(hash);
  if (success) {
    showToast('SHA256 copied to clipboard', 'success');
  } else {
    showToast('Failed to copy', 'error');
  }
}

/**
 * Apply filters from form
 * @param {Event} e - Submit event
 */
function applyFilters(e) {
  e.preventDefault();

  const status = document.getElementById('filter-status').value;
  const platform = document.getElementById('filter-platform').value;
  const search = document.getElementById('filter-search').value;

  updateQueryParams({
    page: '1', // Reset to first page
    status: status || null,
    platform: platform || null,
    search: search || null
  });

  loadAnalyses();
}

/**
 * Clear all filters
 */
function clearFilters() {
  updateQueryParams({
    page: null,
    status: null,
    platform: null,
    search: null
  });
  
  document.getElementById('filter-status').value = '';
  document.getElementById('filter-platform').value = '';
  document.getElementById('filter-search').value = '';
  
  loadAnalyses();
}

/**
 * Navigate to previous page
 */
function goToPrevPage() {
  if (currentPage > 1) {
    updateQueryParams({ page: String(currentPage - 1) });
    loadAnalyses();
  }
}

/**
 * Navigate to next page
 */
function goToNextPage() {
  if (currentPage < totalPages) {
    updateQueryParams({ page: String(currentPage + 1) });
    loadAnalyses();
  }
}

// Event Listeners

// Filter form
filterForm.addEventListener('submit', applyFilters);

// Clear filters
clearFiltersBtn.addEventListener('click', clearFilters);

// Select all
selectAllCheckbox.addEventListener('change', handleSelectAll);

// Bulk actions
bulkDeleteBtn.addEventListener('click', bulkDelete);
bulkCancelBtn.addEventListener('click', () => {
  selectedAnalyses.clear();
  updateBulkActions();
  selectAllCheckbox.checked = false;
});

// Pagination
prevPageBtn.addEventListener('click', goToPrevPage);
nextPageBtn.addEventListener('click', goToNextPage);

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  loadAnalyses();
});

// Make functions globally available for inline handlers
window.deleteAnalysis = deleteAnalysis;
window.copyHash = copyHash;
