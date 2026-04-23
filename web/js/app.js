/**
 * Detonate Web UI - Shared Utilities
 * Common functions used across all pages
 */

// API base URL
const API_BASE = '/api/v1';

/**
 * Format a timestamp as relative time (e.g., "2 hours ago")
 * @param {string} isoString - ISO 8601 timestamp
 * @returns {string} Human-readable relative time
 */
function formatRelativeTime(isoString) {
  if (!isoString) return 'N/A';
  
  const date = new Date(isoString);
  if (isNaN(date.getTime())) return 'N/A';
  
  const now = new Date();
  const diffMs = date - now; // Positive = future, negative = past
  const diffSecs = Math.round(Math.abs(diffMs) / 1000);
  const diffMins = Math.round(diffSecs / 60);
  const diffHours = Math.round(diffMins / 60);
  const diffDays = Math.round(diffHours / 24);
  const diffWeeks = Math.round(diffDays / 7);
  const diffMonths = Math.round(diffDays / 30);
  const diffYears = Math.round(diffDays / 365);
  
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  const isFuture = diffMs > 0;
  
  if (diffSecs < 60) {
    return isFuture ? rtf.format(diffSecs, 'second') : rtf.format(-diffSecs, 'second');
  }
  if (diffMins < 60) {
    return isFuture ? rtf.format(diffMins, 'minute') : rtf.format(-diffMins, 'minute');
  }
  if (diffHours < 24) {
    return isFuture ? rtf.format(diffHours, 'hour') : rtf.format(-diffHours, 'hour');
  }
  if (diffDays < 7) {
    return isFuture ? rtf.format(diffDays, 'day') : rtf.format(-diffDays, 'day');
  }
  if (diffWeeks < 4) {
    return isFuture ? rtf.format(diffWeeks, 'week') : rtf.format(-diffWeeks, 'week');
  }
  if (diffMonths < 12) {
    return isFuture ? rtf.format(diffMonths, 'month') : rtf.format(-diffMonths, 'month');
  }
  if (diffYears < 2) {
    return isFuture ? rtf.format(diffYears, 'year') : rtf.format(-diffYears, 'year');
  }
  
  return formatAbsoluteTime(isoString);
}

/**
 * Cached DateTimeFormat instance for performance
 */
const _dateTimeFormatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit'
});

/**
 * Format a timestamp as absolute date/time
 * @param {string} isoString - ISO 8601 timestamp
 * @param {boolean} includeSeconds - Include seconds in output (default: true for recent items)
 * @returns {string} Formatted date string
 */
function formatAbsoluteTime(isoString, includeSeconds = true) {
  if (!isoString) return 'N/A';
  
  const date = new Date(isoString);
  if (isNaN(date.getTime())) return 'N/A';
  
  if (includeSeconds) {
    return _dateTimeFormatter.format(date);
  }
  
  // Without seconds
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @returns {Promise<boolean>} Success status
 */
async function copyToClipboard(text) {
  // Guard against null/undefined
  if (text == null) return false;
  
  // Try modern async clipboard API first
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(String(text));
      return true;
    } catch (err) {
      // Check for permission denied
      if (err.name === 'NotAllowedError' || err.message.includes('permission')) {
        console.warn('Clipboard permission denied');
        // Fall through to fallback
      } else {
        console.warn('Async clipboard failed:', err);
        // Fall through to fallback
      }
    }
  }
  
  // Fallback for older browsers or when async API fails
  const textarea = document.createElement('textarea');
  textarea.value = String(text);
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  
  try {
    textarea.select();
    const success = document.execCommand('copy');
    return success;
  } catch (e) {
    console.warn('execCommand copy failed:', e);
    return false;
  } finally {
    // Always cleanup
    if (textarea.parentNode) {
      document.body.removeChild(textarea);
    }
  }
}

/**
 * Get current theme from localStorage or system preference
 * @returns {string} 'light' or 'dark'
 */
function getTheme() {
  const stored = localStorage.getItem('theme');
  if (stored) return stored;
  
  // Check system preference
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    return 'dark';
  }
  
  return 'light';
}

/**
 * Toggle between light and dark themes
 * @returns {string} New theme
 */
function toggleTheme() {
  const current = getTheme();
  const newTheme = current === 'light' ? 'dark' : 'light';
  localStorage.setItem('theme', newTheme);
  applyTheme(newTheme);
  return newTheme;
}

/**
 * Apply theme to document
 * @param {string} theme - 'light' or 'dark'
 */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  
  // Update toggle button if it exists
  const toggleBtn = document.getElementById('theme-toggle');
  if (toggleBtn) {
    toggleBtn.textContent = theme === 'light' ? '🌙 Dark' : '☀️ Light';
  }
}

/**
 * Initialize theme on page load
 */
function initTheme() {
  const theme = getTheme();
  applyTheme(theme);
}

/**
 * Show a toast notification
 * @param {string} message - Message to display
 * @param {string} type - 'success', 'error', or 'info'
 * @param {boolean} dismissible - Whether to show close button (default: true)
 * @param {number} duration - Auto-dismiss duration in ms (default: 3000, 0 = no auto-dismiss)
 */
function showToast(message, type = 'info', dismissible = true, duration = 3000) {
  // Remove existing toast
  const existing = document.getElementById('toast');
  if (existing) existing.remove();
  
  const toast = document.createElement('div');
  toast.id = 'toast';
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', 'alert');
  
  // Message container with escaped HTML
  const messageDiv = document.createElement('div');
  messageDiv.className = 'toast-message';
  messageDiv.textContent = message; // textContent automatically escapes HTML
  toast.appendChild(messageDiv);
  
  // Optional close button
  if (dismissible) {
    const closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.innerHTML = '&times;';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.onclick = () => removeToast(toast);
    toast.appendChild(closeBtn);
  }
  
  document.body.appendChild(toast);
  
  // Auto-remove after duration
  if (duration > 0) {
    toast._autoRemoveTimeout = setTimeout(() => {
      removeToast(toast);
    }, duration);
  }
}

/**
 * Remove a toast element with animation
 * @param {HTMLElement} toast - Toast element to remove
 */
function removeToast(toast) {
  if (!toast) return;
  
  // Clear any pending auto-remove timeout
  if (toast._autoRemoveTimeout) {
    clearTimeout(toast._autoRemoveTimeout);
  }
  
  toast.style.animation = 'slideOut 0.3s ease';
  setTimeout(() => {
    if (toast.parentNode) {
      toast.remove();
    }
  }, 300);
}

/**
 * Parse query parameters from URL
 * @returns {Object} Query params as key-value object
 */
function parseQueryParams() {
  const params = new URLSearchParams(window.location.search);
  const result = {};
  for (const [key, value] of params) {
    result[key] = value;
  }
  return result;
}

/**
 * Update URL query params without reloading
 * @param {Object} params - New params to set
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
 * Format file size in bytes to human-readable string
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size
 */
function formatFileSize(bytes) {
  if (!bytes) return '0 B';
  
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let size = bytes;
  
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024;
    i++;
  }
  
  return `${size.toFixed(2)} ${units[i]}`;
}

/**
 * Truncate a string to specified length
 * @param {string} str - String to truncate
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated string
 */
function truncate(str, maxLength = 50) {
  if (!str || str.length <= maxLength) return str;
  return str.substring(0, maxLength) + '...';
}

/**
 * Escape HTML to prevent XSS
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  if (typeof str !== 'string') str = String(str);
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Debounce a function
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in ms
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Initialize theme on load
document.addEventListener('DOMContentLoaded', initTheme);
