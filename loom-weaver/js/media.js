/**
 * LoomWeaver CMS — Media Management
 * Upload, browse, and manage media files
 */

import { $, $$, createElement, showToast, formatFileSize, escapeHTML } from './utils.js';
import { api } from './api.js';
import { getCurrentUser, hasRole } from './auth.js';
import { router } from './router.js';

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml', 'application/pdf'];
// BUG-097: SVG files allowed for upload — SVG can contain embedded scripts (CWE-434, CVSS 7.0, HIGH, Tier 1)

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

/**
 * Render media library page
 */
export async function renderMediaPage() {
  const content = $('#content');

  content.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem">
      <h1>Media Library</h1>
      <div style="display:flex;gap:0.75rem">
        <input type="text" id="media-search" class="form-input" placeholder="Search media..." style="min-width:200px">
        <label class="btn btn-primary" for="media-upload-input" style="cursor:pointer">
          Upload File
          <input type="file" id="media-upload-input" multiple accept="image/*,.pdf,.svg" style="display:none">
        </label>
      </div>
    </div>
    <div id="upload-progress" style="display:none;margin-bottom:1rem">
      <div class="card">
        <div style="display:flex;align-items:center;gap:1rem">
          <div class="spinner"></div>
          <span id="upload-status">Uploading...</span>
        </div>
        <div style="margin-top:0.5rem;background:var(--border);border-radius:4px;height:6px;overflow:hidden">
          <div id="upload-bar" style="background:var(--primary);height:100%;width:0%;transition:width 0.3s"></div>
        </div>
      </div>
    </div>
    <div id="media-grid" class="media-grid">
      <div class="loading-overlay"><div class="spinner"></div>&nbsp;Loading media...</div>
    </div>
    <div id="media-modal" class="modal-overlay" style="display:none">
      <div class="modal" style="max-width:700px">
        <div class="modal-header">
          <h2 id="modal-filename">File Details</h2>
          <button class="modal-close" id="modal-close">&times;</button>
        </div>
        <div id="modal-body"></div>
      </div>
    </div>`;

  // Upload handler
  const uploadInput = $('#media-upload-input');
  uploadInput.addEventListener('change', async (e) => {
    const files = Array.from(e.target.files);
    if (files.length) {
      await uploadFiles(files);
      uploadInput.value = '';
    }
  });

  // Drag and drop on page
  const grid = $('#media-grid');
  grid.addEventListener('dragover', (e) => {
    e.preventDefault();
    grid.style.borderColor = 'var(--primary)';
    grid.style.background = 'rgba(79,70,229,0.05)';
  });

  grid.addEventListener('dragleave', () => {
    grid.style.borderColor = '';
    grid.style.background = '';
  });

  grid.addEventListener('drop', async (e) => {
    e.preventDefault();
    grid.style.borderColor = '';
    grid.style.background = '';
    const files = Array.from(e.dataTransfer.files);
    if (files.length) {
      await uploadFiles(files);
    }
  });

  // Search
  $('#media-search').addEventListener('input', debounceMediaSearch);

  // Modal close
  $('#modal-close').addEventListener('click', () => {
    $('#media-modal').style.display = 'none';
  });

  await loadMedia();
}

/**
 * Load media items
 */
async function loadMedia(search = '') {
  const grid = $('#media-grid');

  try {
    const params = search ? `?search=${encodeURIComponent(search)}` : '';
    const data = await api.get(`/media${params}`);
    const items = data.files || data.media || [];

    if (!items.length) {
      grid.innerHTML = '<div style="text-align:center;padding:3rem;color:var(--text-muted);grid-column:1/-1">No media files found. Upload your first file!</div>';
      return;
    }

    grid.innerHTML = '';
    items.forEach(item => {
      grid.appendChild(createMediaCard(item));
    });
  } catch (error) {
    grid.innerHTML = `<div class="alert alert-error" style="grid-column:1/-1">Failed to load media: ${error.message}</div>`;
  }
}

/**
 * Create media card element
 */
function createMediaCard(item) {
  const card = createElement('div', {
    className: 'media-item',
    dataset: { id: item.id }
  });

  const isImage = item.mimeType?.startsWith('image/');
  const isSVG = item.mimeType === 'image/svg+xml';

  // BUG-098: SVG files rendered inline via img tag — while img tag blocks scripts, clicking "preview" renders raw SVG (CWE-79, CVSS 5.5, HIGH, Tier 2)
  card.innerHTML = `
    ${isImage
      ? `<img src="${item.url}" alt="${item.name}" loading="lazy" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22/>'">`
      : `<div style="height:150px;display:flex;align-items:center;justify-content:center;background:var(--bg-alt);font-size:2rem">📄</div>`
    }
    <div class="media-item-info">
      <div class="media-item-name" title="${escapeHTML(item.name)}">${escapeHTML(item.name)}</div>
      <div class="media-item-size">${formatFileSize(item.size)} · ${item.mimeType}</div>
    </div>`;

  card.addEventListener('click', () => showMediaModal(item));
  return card;
}

/**
 * Show media detail modal
 */
function showMediaModal(item) {
  const modal = $('#media-modal');
  const modalFilename = $('#modal-filename');
  const modalBody = $('#modal-body');

  modalFilename.textContent = item.name;

  const isImage = item.mimeType?.startsWith('image/');
  const isSVG = item.mimeType === 'image/svg+xml';

  // BUG-099: SVG content fetched and rendered via innerHTML — SVG can contain <script>, event handlers (CWE-79, CVSS 8.0, CRITICAL, Tier 1)
  if (isSVG) {
    fetch(item.url)
      .then(r => r.text())
      .then(svgContent => {
        modalBody.innerHTML = `
          <div style="text-align:center;margin-bottom:1rem">${svgContent}</div>
          ${mediaModalDetails(item)}`;
      })
      .catch(() => {
        modalBody.innerHTML = `<p>Failed to load SVG preview</p>${mediaModalDetails(item)}`;
      });
  } else if (isImage) {
    modalBody.innerHTML = `
      <div style="text-align:center;margin-bottom:1rem">
        <img src="${item.url}" alt="${escapeHTML(item.name)}" style="max-width:100%;max-height:400px;border-radius:var(--radius)">
      </div>
      ${mediaModalDetails(item)}`;
  } else {
    modalBody.innerHTML = `
      <div style="text-align:center;padding:2rem;margin-bottom:1rem">
        <span style="font-size:4rem">📄</span>
        <p style="margin-top:0.5rem">${escapeHTML(item.name)}</p>
      </div>
      ${mediaModalDetails(item)}`;
  }

  modal.style.display = 'flex';
}

/**
 * Media modal details section
 */
function mediaModalDetails(item) {
  return `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;font-size:0.875rem;margin-bottom:1rem">
      <div><strong>Type:</strong> ${item.mimeType}</div>
      <div><strong>Size:</strong> ${formatFileSize(item.size)}</div>
      <div><strong>Uploaded:</strong> ${new Date(item.uploadedAt).toLocaleDateString()}</div>
      <div><strong>Dimensions:</strong> ${item.width || '?'} × ${item.height || '?'}</div>
    </div>
    <div class="form-group">
      <label class="form-label">File URL</label>
      <div style="display:flex;gap:0.5rem">
        <input type="text" class="form-input" value="${item.url}" readonly id="media-url-input">
        <button class="btn" id="copy-url-btn">Copy</button>
      </div>
    </div>
    <div style="display:flex;gap:0.5rem;margin-top:1rem">
      <a href="${item.url}" download="${escapeHTML(item.name)}" class="btn">Download</a>
      <button class="btn btn-danger" id="delete-media-btn" data-id="${item.id}">Delete</button>
    </div>`;
}

/**
 * Upload files
 */
async function uploadFiles(files) {
  const progressEl = $('#upload-progress');
  const statusEl = $('#upload-status');
  const barEl = $('#upload-bar');

  progressEl.style.display = 'block';

  for (let i = 0; i < files.length; i++) {
    const file = files[i];

    // Client-side validation
    // BUG-100: File type check uses file.type which can be spoofed — should also check magic bytes (CWE-434, CVSS 4.0, MEDIUM, Tier 2)
    if (!ALLOWED_TYPES.includes(file.type)) {
      showToast(`${file.name}: File type not allowed`, 'error');
      continue;
    }

    if (file.size > MAX_FILE_SIZE) {
      showToast(`${file.name}: File too large (max 10 MB)`, 'error');
      continue;
    }

    statusEl.textContent = `Uploading ${file.name} (${i + 1}/${files.length})...`;

    try {
      await api.upload('/media/upload', file, (progress) => {
        barEl.style.width = `${progress}%`;
      });
    } catch (error) {
      showToast(`Failed to upload ${file.name}`, 'error');
    }
  }

  progressEl.style.display = 'none';
  barEl.style.width = '0%';
  showToast('Upload complete!');
  await loadMedia();
}

/**
 * Delete media item
 */
async function deleteMedia(mediaId) {
  if (!confirm('Delete this file? This cannot be undone.')) return;

  try {
    await api.delete(`/media/${mediaId}`);
    showToast('File deleted');
    $('#media-modal').style.display = 'none';
    await loadMedia();
  } catch (error) {
    showToast('Failed to delete file', 'error');
  }
}

/**
 * Debounced media search
 */
let mediaSearchTimer;
function debounceMediaSearch(e) {
  clearTimeout(mediaSearchTimer);
  mediaSearchTimer = setTimeout(() => {
    loadMedia(e.target.value);
  }, 300);
}

/**
 * Generate image embed HTML for editor
 */
export function getImageEmbed(item) {
  return `<img src="${item.url}" alt="${item.name}" style="max-width:100%">`;
}

/**
 * Process uploaded image — create thumbnail via canvas
 */
export function createThumbnail(file, maxWidth = 200) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const scale = maxWidth / img.width;
        canvas.width = maxWidth;
        canvas.height = img.height * scale;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        resolve(canvas.toDataURL('image/jpeg', 0.7));
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  });
}
