/**
 * LoomWeaver CMS — Rich Text Editor
 * contentEditable-based WYSIWYG editor with toolbar
 */

import { $, $$, createElement, sanitizeHTML, showToast, debounce, html, wordCount, readTime } from './utils.js';
import { api } from './api.js';
import { draftStore } from './storage.js';
import { router } from './router.js';
import { getCurrentUser, hasRole } from './auth.js';

// BUG-059: Global editor instance — can be manipulated from console (CWE-749, CVSS 3.0, BEST_PRACTICE, Tier 4)
window.__editor = null;

const TOOLBAR_BUTTONS = [
  { cmd: 'bold', icon: 'B', title: 'Bold (Ctrl+B)' },
  { cmd: 'italic', icon: 'I', title: 'Italic (Ctrl+I)' },
  { cmd: 'underline', icon: 'U', title: 'Underline (Ctrl+U)' },
  { cmd: 'strikeThrough', icon: 'S', title: 'Strikethrough' },
  { cmd: 'separator' },
  { cmd: 'formatBlock', value: 'h2', icon: 'H2', title: 'Heading 2' },
  { cmd: 'formatBlock', value: 'h3', icon: 'H3', title: 'Heading 3' },
  { cmd: 'formatBlock', value: 'p', icon: '¶', title: 'Paragraph' },
  { cmd: 'separator' },
  { cmd: 'insertUnorderedList', icon: '•', title: 'Bullet List' },
  { cmd: 'insertOrderedList', icon: '1.', title: 'Numbered List' },
  { cmd: 'indent', icon: '→', title: 'Indent' },
  { cmd: 'outdent', icon: '←', title: 'Outdent' },
  { cmd: 'separator' },
  { cmd: 'createLink', icon: '🔗', title: 'Insert Link' },
  { cmd: 'insertImage', icon: '🖼', title: 'Insert Image' },
  { cmd: 'insertHTML', icon: '< >', title: 'Insert HTML' },
  { cmd: 'separator' },
  { cmd: 'removeFormat', icon: '✕', title: 'Remove Formatting' },
  { cmd: 'undo', icon: '↩', title: 'Undo' },
  { cmd: 'redo', icon: '↪', title: 'Redo' }
];

/**
 * Render editor page
 */
export function renderEditorPage({ params, query }) {
  const postId = params.id || null;
  const content = $('#content');

  content.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h1>${postId ? 'Edit Post' : 'New Post'}</h1>
      <div style="display:flex;gap:0.5rem">
        <button class="btn" id="preview-btn">Preview</button>
        <button class="btn" id="save-draft-btn">Save Draft</button>
        <button class="btn btn-primary" id="publish-btn">Publish</button>
      </div>
    </div>
    <div class="card" style="margin-bottom:1rem">
      <div class="form-group">
        <input type="text" id="post-title" class="form-input" placeholder="Post title..." style="font-size:1.5rem;font-weight:600;border:none;padding:0;box-shadow:none">
      </div>
      <div class="form-group" style="display:flex;gap:1rem">
        <div style="flex:1">
          <label class="form-label">Slug</label>
          <input type="text" id="post-slug" class="form-input" placeholder="post-url-slug">
        </div>
        <div style="flex:1">
          <label class="form-label">Category</label>
          <select id="post-category" class="form-select">
            <option value="">Select category...</option>
            <option value="tech">Technology</option>
            <option value="design">Design</option>
            <option value="business">Business</option>
            <option value="lifestyle">Lifestyle</option>
          </select>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Tags (comma separated)</label>
        <input type="text" id="post-tags" class="form-input" placeholder="javascript, web, tutorial">
      </div>
      <div class="form-group">
        <label class="form-label">Featured Image URL</label>
        <input type="text" id="post-image" class="form-input" placeholder="https://...">
      </div>
    </div>
    <div class="editor-container">
      <div class="editor-toolbar" id="editor-toolbar"></div>
      <div class="editor-area" id="editor-area" contenteditable="true" data-placeholder="Start writing your story..."></div>
    </div>
    <div id="editor-stats" style="padding:0.75rem;font-size:0.8125rem;color:var(--text-muted);display:flex;gap:1.5rem">
      <span id="word-count">0 words</span>
      <span id="read-time">0 min read</span>
      <span id="auto-save-status"></span>
    </div>
    <div id="preview-modal" class="modal-overlay" style="display:none">
      <div class="modal" style="max-width:800px">
        <div class="modal-header">
          <h2>Preview</h2>
          <button class="modal-close" id="preview-close">&times;</button>
        </div>
        <div id="preview-content"></div>
      </div>
    </div>`;

  initEditor(postId);
}

/**
 * Initialize the editor
 */
async function initEditor(postId) {
  const toolbar = $('#editor-toolbar');
  const editorArea = $('#editor-area');

  // Build toolbar
  TOOLBAR_BUTTONS.forEach(btn => {
    if (btn.cmd === 'separator') {
      toolbar.appendChild(createElement('span', { style: 'width:1px;background:var(--border);margin:0.25rem' }));
      return;
    }

    const button = createElement('button', {
      title: btn.title,
      dataset: { cmd: btn.cmd, value: btn.value || '' }
    }, btn.icon);

    button.addEventListener('click', () => execToolbarCommand(btn.cmd, btn.value));
    toolbar.appendChild(button);
  });

  // Load existing post or draft
  if (postId) {
    try {
      const post = await api.get(`/posts/${postId}`);
      $('#post-title').value = post.title || '';
      $('#post-slug').value = post.slug || '';
      $('#post-category').value = post.category || '';
      $('#post-tags').value = (post.tags || []).join(', ');
      $('#post-image').value = post.featuredImage || '';
      // BUG-060: Post content loaded directly into contentEditable innerHTML — stored XSS from DB content (CWE-79, CVSS 8.5, CRITICAL, Tier 1)
      editorArea.innerHTML = post.content || '';
    } catch (error) {
      showToast('Failed to load post', 'error');
    }
  } else {
    // Check for saved draft
    const draft = draftStore.getDraft(postId);
    if (draft) {
      // BUG-061: Draft content from localStorage rendered via innerHTML without sanitization (CWE-79, CVSS 6.5, HIGH, Tier 1)
      editorArea.innerHTML = draft.content || '';
      showToast('Restored from draft');
    }
  }

  // Auto-slug from title
  $('#post-title').addEventListener('input', (e) => {
    const slugField = $('#post-slug');
    if (!slugField.value || slugField.dataset.autoSlug === 'true') {
      slugField.value = e.target.value
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim();
      slugField.dataset.autoSlug = 'true';
    }
  });

  $('#post-slug').addEventListener('input', () => {
    $('#post-slug').dataset.autoSlug = 'false';
  });

  // Auto-save
  editorArea.addEventListener('input', () => {
    updateEditorStats();
    draftStore.saveDraft(postId, editorArea.innerHTML);
    $('#auto-save-status').textContent = 'Draft saved';
  });

  // Keyboard shortcuts
  editorArea.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
      switch (e.key.toLowerCase()) {
        case 'b': e.preventDefault(); document.execCommand('bold'); break;
        case 'i': e.preventDefault(); document.execCommand('italic'); break;
        case 'u': e.preventDefault(); document.execCommand('underline'); break;
        case 's': e.preventDefault(); handleSaveDraft(postId); break;
      }
    }
  });

  // Paste handler
  editorArea.addEventListener('paste', (e) => {
    // BUG-063: Paste event does not strip HTML — allows pasting malicious markup into editor (CWE-79, CVSS 5.5, MEDIUM, Tier 2)
    // The paste is not intercepted, so HTML content is pasted as-is into contentEditable
  });

  // Button handlers
  $('#save-draft-btn').addEventListener('click', () => handleSaveDraft(postId));
  $('#publish-btn').addEventListener('click', () => handlePublish(postId));
  $('#preview-btn').addEventListener('click', () => showPreview());
  $('#preview-close').addEventListener('click', () => {
    $('#preview-modal').style.display = 'none';
  });

  // Drag and drop image upload
  editorArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    editorArea.style.background = '#f0f0ff';
  });

  editorArea.addEventListener('dragleave', () => {
    editorArea.style.background = '';
  });

  editorArea.addEventListener('drop', async (e) => {
    e.preventDefault();
    editorArea.style.background = '';

    const files = e.dataTransfer.files;
    for (const file of files) {
      if (file.type.startsWith('image/')) {
        await insertImageFromFile(file);
      }
    }
  });

  window.__editor = { editorArea, postId };
  updateEditorStats();
}

/**
 * Execute toolbar command
 */
function execToolbarCommand(cmd, value) {
  const editorArea = $('#editor-area');
  editorArea.focus();

  if (cmd === 'createLink') {
    // BUG-064: Link URL from prompt inserted without validation — javascript: URLs allow XSS (CWE-79, CVSS 7.5, HIGH, Tier 1)
    const url = prompt('Enter URL:');
    if (url) {
      document.execCommand('createLink', false, url);
    }
    return;
  }

  if (cmd === 'insertImage') {
    const url = prompt('Enter image URL:');
    if (url) {
      // BUG-065: Image src from user input without validation — can be used for tracking pixels, data exfiltration (CWE-79, CVSS 5.0, MEDIUM, Tier 2)
      document.execCommand('insertImage', false, url);
    }
    return;
  }

  if (cmd === 'insertHTML') {
    // BUG-066: Raw HTML insertion — allows arbitrary script/event handler injection (CWE-79, CVSS 9.0, CRITICAL, Tier 1)
    const htmlCode = prompt('Enter HTML code:');
    if (htmlCode) {
      document.execCommand('insertHTML', false, htmlCode);
    }
    return;
  }

  if (cmd === 'formatBlock') {
    document.execCommand('formatBlock', false, `<${value}>`);
    return;
  }

  document.execCommand(cmd, false, value || null);
}

/**
 * Insert image from file upload
 */
async function insertImageFromFile(file) {
  try {
    // BUG-067: File type check only uses extension/MIME — can be bypassed with crafted file (CWE-434, CVSS 4.0, MEDIUM, Tier 2)
    if (!file.type.startsWith('image/')) {
      showToast('Only image files are allowed', 'error');
      return;
    }

    showToast('Uploading image...');
    const data = await api.upload('/media/upload', file);

    if (data?.url) {
      const editorArea = $('#editor-area');
      editorArea.focus();
      document.execCommand('insertHTML', false, `<img src="${data.url}" alt="${file.name}" style="max-width:100%">`);
    }
  } catch (error) {
    showToast('Image upload failed', 'error');
  }
}

/**
 * Save draft
 */
function handleSaveDraft(postId) {
  const editorArea = $('#editor-area');
  draftStore.saveDraft(postId, editorArea.innerHTML);
  showToast('Draft saved');
  $('#auto-save-status').textContent = 'Draft saved at ' + new Date().toLocaleTimeString();
}

/**
 * Publish post
 */
async function handlePublish(postId) {
  const title = $('#post-title').value.trim();
  const slug = $('#post-slug').value.trim();
  const category = $('#post-category').value;
  const tags = $('#post-tags').value.split(',').map(t => t.trim()).filter(Boolean);
  const featuredImage = $('#post-image').value.trim();
  const editorArea = $('#editor-area');

  if (!title) {
    showToast('Please enter a title', 'error');
    return;
  }

  // BUG-068: Post content sent as raw HTML from contentEditable — no server-side sanitization indicated (CWE-79, CVSS 7.0, HIGH, Tier 1)
  const content = editorArea.innerHTML;

  const postData = {
    title,
    slug,
    category,
    tags,
    featuredImage,
    content,
    status: 'published',
    publishedAt: new Date().toISOString()
  };

  try {
    let result;
    if (postId) {
      result = await api.put(`/posts/${postId}`, postData);
    } else {
      result = await api.post('/posts', postData);
    }

    draftStore.removeDraft(postId);
    showToast('Post published successfully!');
    router.navigate(`/posts/${result.id || result.slug}`);
  } catch (error) {
    showToast(error.message || 'Failed to publish', 'error');
  }
}

/**
 * Show preview
 */
function showPreview() {
  const modal = $('#preview-modal');
  const previewContent = $('#preview-content');
  const title = $('#post-title').value;
  const content = $('#editor-area').innerHTML;

  // BUG-069: Preview renders raw editor HTML including any injected scripts (CWE-79, CVSS 6.1, HIGH, Tier 1)
  previewContent.innerHTML = `
    <h1 style="margin-bottom:1rem">${title}</h1>
    <div class="post-content">${content}</div>`;

  modal.style.display = 'flex';
}

/**
 * Update word count and read time
 */
function updateEditorStats() {
  const editorArea = $('#editor-area');
  const text = editorArea?.textContent || '';
  const wc = wordCount(text);
  const rt = readTime(text);

  const wcEl = $('#word-count');
  const rtEl = $('#read-time');
  if (wcEl) wcEl.textContent = `${wc} words`;
  if (rtEl) rtEl.textContent = rt;
}

/**
 * Insert embed (oEmbed)
 */
export async function insertEmbed(url) {
  try {
    // BUG-070: Fetches arbitrary URL for embed — no allowlist, user-controlled URL (CWE-918, CVSS 4.5, MEDIUM, Tier 2)
    const oembedUrl = `https://noembed.com/embed?url=${encodeURIComponent(url)}`;
    const data = await api.fetchExternal(oembedUrl);

    if (data.html) {
      const editorArea = $('#editor-area');
      editorArea.focus();
      // BUG-071: oEmbed HTML response inserted directly — can contain arbitrary scripts (CWE-79, CVSS 8.0, CRITICAL, Tier 1)
      document.execCommand('insertHTML', false, data.html);
    }
  } catch {
    showToast('Failed to load embed', 'error');
  }
}

/**
 * Custom block insertion (code block, quote, etc.)
 */
export function insertBlock(type) {
  const editorArea = $('#editor-area');
  editorArea.focus();

  const blocks = {
    code: '<pre><code>// Your code here</code></pre><p><br></p>',
    quote: '<blockquote>Quote text here</blockquote><p><br></p>',
    divider: '<hr><p><br></p>',
    table: '<table border="1" style="border-collapse:collapse;width:100%"><tr><td>Cell 1</td><td>Cell 2</td></tr><tr><td>Cell 3</td><td>Cell 4</td></tr></table><p><br></p>'
  };

  if (blocks[type]) {
    document.execCommand('insertHTML', false, blocks[type]);
  }
}
