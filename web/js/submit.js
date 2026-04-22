/**
 * Submit Analysis Page - File upload, hash computation, and submission
 */

// State
let selectedFile = null;
let fileHash = null;
let isSubmitting = false;
let currentXhr = null; // Track XHR for abort on cancel

// DOM Elements - null-safe initialization
const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const infoFilename = document.getElementById('info-filename');
const infoSize = document.getElementById('info-size');
const infoSha256 = document.getElementById('info-sha256');
const analysisForm = document.getElementById('analysis-form');
const submitBtn = document.getElementById('submit-btn');
const cancelBtn = document.getElementById('cancel-btn');
const progressContainer = document.getElementById('progress-container');
const progressFill = document.getElementById('progress-fill');
const progressText = document.getElementById('progress-text');
const messageContainer = document.getElementById('message-container');

// Dependency validation - ensure app.js utilities are loaded
if (typeof escapeHtml !== 'function' || typeof formatFileSize !== 'function' || typeof showToast !== 'function') {
  console.error('submit.js requires app.js to be loaded first');
}
if (typeof API_BASE === 'undefined') {
  console.error('submit.js requires API_BASE from app.js');
}

/**
 * Handle file selection (both drag-drop and click)
 * @param {File} file - Selected file
 */
async function handleFileSelect(file) {
  if (!file) return;

  selectedFile = file;
  
  // Display file info
  infoFilename.textContent = escapeHtml(file.name);
  infoSize.textContent = formatFileSize(file.size);
  infoSha256.textContent = 'Computing hash...';
  
  fileInfo.style.display = 'block';
  submitBtn.disabled = true;
  submitBtn.textContent = 'Computing hash...';

  // Compute SHA256 hash
  try {
    fileHash = await computeFileHash(file);
    infoSha256.textContent = fileHash;
    infoSha256.title = fileHash;
    
    submitBtn.disabled = false;
    submitBtn.textContent = 'Start Analysis';
    
    showToast('File selected: ' + file.name, 'success');
  } catch (error) {
    console.error('Failed to compute file hash:', error);
    infoSha256.textContent = 'Hash computation failed';
    showMessage('Failed to compute file hash: ' + error.message, 'error');
    submitBtn.disabled = true;
  }
}

/**
 * Compute SHA256 hash of a file using Web Crypto API
 * @param {File} file - File to hash
 * @returns {Promise<string>} Hex-encoded SHA256 hash
 */
async function computeFileHash(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

/**
 * Submit analysis to the server
 * @param {Event} e - Form submit event
 */
async function submitAnalysis(e) {
  e.preventDefault();
  
  if (!selectedFile || !fileHash) {
    showMessage('Please select a file first', 'error');
    return;
  }

  if (isSubmitting) return;
  
  isSubmitting = true;
  submitBtn.disabled = true;
  cancelBtn.style.display = 'inline-block';
  progressContainer.style.display = 'block';
  progressFill.style.width = '0%';
  progressText.textContent = 'Preparing upload...';
  messageContainer.innerHTML = '';

  // Get form values
  const platform = document.getElementById('platform').value;
  const arch = document.getElementById('arch').value;
  const timeout = parseInt(document.getElementById('timeout').value, 10);
  const notes = document.getElementById('notes').value.trim();

  // Build form data
  const formData = new FormData();
  formData.append('file', selectedFile);
  formData.append('platform', platform);
  formData.append('arch', arch);
  formData.append('timeout', String(timeout));
  if (notes) {
    formData.append('notes', notes);
  }

  try {
    // Create XHR for progress tracking
    const xhr = new XMLHttpRequest();
    currentXhr = xhr; // Track for abort on cancel
    
    // Track upload progress
    xhr.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 100);
        progressFill.style.width = percent + '%';
        progressText.textContent = `Uploading... ${percent}%`;
      }
    });

    // Handle completion
    xhr.addEventListener('load', () => {
      currentXhr = null; // Clear reference
      if (xhr.status >= 200 && xhr.status < 300) {
        progressFill.style.width = '100%';
        progressText.textContent = 'Upload complete! Redirecting...';
        showToast('Analysis submitted successfully', 'success');
        
        // Parse response and redirect
        try {
          const response = JSON.parse(xhr.responseText);
          const sessionId = response.session_id;
          
          setTimeout(() => {
            window.location.href = `/web/analysis.html?id=${sessionId}`;
          }, 1000);
        } catch (parseErr) {
          console.error('Failed to parse response:', parseErr);
          setTimeout(() => {
            window.location.href = '/web/analyses.html';
          }, 1000);
        }
      } else {
        let errorMsg = 'Upload failed';
        try {
          const errorData = JSON.parse(xhr.responseText);
          errorMsg = errorData.detail || errorData.message || errorMsg;
        } catch (e) {
          // Use default error message
        }
        handleSubmissionError(new Error(errorMsg));
      }
    });

    // Handle network errors
    xhr.addEventListener('error', () => {
      currentXhr = null;
      handleSubmissionError(new Error('Network error during upload'));
    });

    xhr.addEventListener('abort', () => {
      currentXhr = null;
      handleSubmissionError(new Error('Upload cancelled'));
    });

    // Open and send
    xhr.open('POST', `${API_BASE}/analyze`);
    xhr.send(formData);

  } catch (error) {
    currentXhr = null;
    handleSubmissionError(error);
  }
}

/**
 * Handle successful submission
 * @param {Object} response - API response
 */
function handleSubmissionSuccess(response) {
  progressFill.style.width = '100%';
  progressText.textContent = 'Analysis started!';
  showMessage('Analysis submitted successfully! Redirecting to results...', 'success');
  
  setTimeout(() => {
    window.location.href = `/web/analysis.html?id=${response.session_id}`;
  }, 1500);
}

/**
 * Handle submission error
 * @param {Error} error - Error that occurred
 */
function handleSubmissionError(error) {
  console.error('Submission error:', error);
  
  isSubmitting = false;
  submitBtn.disabled = false;
  cancelBtn.style.display = 'none';
  progressContainer.style.display = 'none';
  
  showMessage('Failed to submit analysis: ' + error.message, 'error');
  showToast('Submission failed', 'error');
}

/**
 * Show a message in the message container
 * @param {string} message - Message to display
 * @param {string} type - 'success' or 'error'
 */
function showMessage(message, type = 'info') {
  const color = type === 'success' ? 'var(--primary)' : '#d32f2f';
  messageContainer.innerHTML = `
    <article style="border-left: 4px solid ${color};">
      <p style="margin: 0;">${escapeHtml(message)}</p>
    </article>
  `;
}

/**
 * Reset the form to initial state
 */
function resetForm() {
  // Abort any in-progress XHR to prevent memory leaks
  if (currentXhr) {
    currentXhr.abort();
    currentXhr = null;
  }
  
  selectedFile = null;
  fileHash = null;
  isSubmitting = false;
  
  // Null-safe DOM access
  if (fileInput) fileInput.value = '';
  if (fileInfo) fileInfo.style.display = 'none';
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Start Analysis';
  }
  if (cancelBtn) cancelBtn.style.display = 'none';
  if (progressContainer) progressContainer.style.display = 'none';
  if (progressFill) progressFill.style.width = '0%';
  if (messageContainer) messageContainer.innerHTML = '';
  
  // Reset form fields with null checks
  const platform = document.getElementById('platform');
  const arch = document.getElementById('arch');
  const timeout = document.getElementById('timeout');
  const notes = document.getElementById('notes');
  if (platform) platform.value = 'windows';
  if (arch) arch.value = 'x86_64';
  if (timeout) timeout.value = '60';
  if (notes) notes.value = '';
}

// Event Listeners

// Upload zone click
uploadZone.addEventListener('click', () => {
  if (!isSubmitting) {
    fileInput.click();
  }
});

// File input change
fileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files[0]) {
    handleFileSelect(e.target.files[0]);
  }
});

// Drag and drop
uploadZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  if (!isSubmitting) {
    uploadZone.classList.add('dragover');
  }
});

uploadZone.addEventListener('dragleave', (e) => {
  e.preventDefault();
  uploadZone.classList.remove('dragover');
});

uploadZone.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadZone.classList.remove('dragover');
  
  if (!isSubmitting && e.dataTransfer.files && e.dataTransfer.files[0]) {
    handleFileSelect(e.dataTransfer.files[0]);
  }
});

// Form submission
analysisForm.addEventListener('submit', submitAnalysis);

// Cancel button - abort upload and reset
if (cancelBtn) {
  cancelBtn.addEventListener('click', () => {
    if (confirm('Cancel the upload?')) {
      resetForm();
      showToast('Upload cancelled', 'info');
    }
  });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  submitBtn.disabled = true;
});
