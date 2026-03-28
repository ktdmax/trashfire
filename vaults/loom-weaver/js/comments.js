/**
 * LoomWeaver CMS — Comment System
 * Threaded comments with replies, voting, and moderation
 */

import { $, $$, createElement, sanitizeHTML, escapeHTML, html, formatDate, timeAgo, showToast } from './utils.js';
import { api } from './api.js';
import { getCurrentUser, hasRole } from './auth.js';
import { tokenStore } from './storage.js';

/**
 * Render comments section for a post
 */
export async function renderComments(postId) {
  const container = $('#comments-container');
  if (!container) return;

  try {
    const data = await api.get(`/posts/${postId}/comments`);
    const comments = data.comments || [];

    container.innerHTML = '';

    // Comment form
    const user = getCurrentUser();
    if (user) {
      container.appendChild(createCommentForm(postId));
    } else {
      container.innerHTML += '<p style="margin-bottom:1rem;color:var(--text-muted)"><a href="#/login">Sign in</a> to leave a comment.</p>';
    }

    // Comment list
    const listEl = createElement('div', { className: 'comment-list', id: 'comment-list' });

    if (!comments.length) {
      listEl.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:2rem">No comments yet. Be the first!</p>';
    } else {
      // Build threaded comments
      const threaded = buildCommentTree(comments);
      threaded.forEach(comment => {
        listEl.appendChild(renderComment(comment, postId, 0));
      });
    }

    container.appendChild(listEl);

    // BUG-087: Memory leak — comment event listeners are added but never cleaned up on navigation (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 4)

  } catch (error) {
    container.innerHTML = `<div class="alert alert-error">Failed to load comments: ${error.message}</div>`;
  }
}

/**
 * Build threaded comment tree
 */
function buildCommentTree(comments) {
  const map = {};
  const roots = [];

  comments.forEach(c => {
    map[c.id] = { ...c, children: [] };
  });

  comments.forEach(c => {
    if (c.parentId && map[c.parentId]) {
      map[c.parentId].children.push(map[c.id]);
    } else {
      roots.push(map[c.id]);
    }
  });

  return roots;
}

/**
 * Render a single comment with nested replies
 */
function renderComment(comment, postId, depth = 0) {
  const user = getCurrentUser();
  const isAuthor = user && (user.sub === comment.authorId || user.id === comment.authorId);
  const isAdmin = hasRole('admin');
  const isMod = hasRole('moderator');

  const el = createElement('div', {
    className: 'comment',
    style: depth > 0 ? `margin-left:${Math.min(depth * 1.5, 4.5)}rem` : '',
    id: `comment-${comment.id}`
  });

  // BUG-088: Comment author display name rendered via innerHTML — stored XSS (CWE-79, CVSS 7.5, HIGH, Tier 1)
  // BUG-089: Comment body rendered via innerHTML with only basic sanitization (strips script tags) — mXSS possible (CWE-79, CVSS 8.0, CRITICAL, Tier 1)
  const sanitizedBody = sanitizeHTML(comment.body || '');

  el.innerHTML = `
    <div class="comment-header">
      <span class="comment-author">${comment.author?.displayName || comment.author?.username || 'Anonymous'}</span>
      <span class="comment-date">${timeAgo(comment.createdAt)}</span>
    </div>
    <div class="comment-body">${sanitizedBody}</div>
    <div class="comment-actions">
      <button class="btn btn-sm vote-btn" data-action="upvote" data-id="${comment.id}">
        ▲ ${comment.upvotes || 0}
      </button>
      <button class="btn btn-sm vote-btn" data-action="downvote" data-id="${comment.id}">
        ▼ ${comment.downvotes || 0}
      </button>
      ${user ? `<button class="btn btn-sm reply-btn" data-id="${comment.id}">Reply</button>` : ''}
      ${isAuthor ? `<button class="btn btn-sm edit-comment-btn" data-id="${comment.id}">Edit</button>` : ''}
      ${(isAuthor || isAdmin || isMod) ? `<button class="btn btn-sm btn-danger delete-comment-btn" data-id="${comment.id}">Delete</button>` : ''}
      <button class="btn btn-sm report-btn" data-id="${comment.id}">Report</button>
    </div>
    <div class="reply-form-container" id="reply-to-${comment.id}" style="display:none;margin-top:0.75rem"></div>`;

  // Attach event handlers
  setTimeout(() => {
    // Vote buttons
    $$('.vote-btn', el).forEach(btn => {
      btn.addEventListener('click', () => handleVote(postId, comment.id, btn.dataset.action));
    });

    // Reply button
    const replyBtn = $(`.reply-btn[data-id="${comment.id}"]`, el);
    if (replyBtn) {
      replyBtn.addEventListener('click', () => toggleReplyForm(comment.id, postId));
    }

    // Edit button
    const editBtn = $(`.edit-comment-btn[data-id="${comment.id}"]`, el);
    if (editBtn) {
      editBtn.addEventListener('click', () => startEditComment(comment));
    }

    // Delete button
    const deleteBtn = $(`.delete-comment-btn[data-id="${comment.id}"]`, el);
    if (deleteBtn) {
      deleteBtn.addEventListener('click', () => handleDeleteComment(postId, comment.id));
    }

    // Report button
    const reportBtn = $(`.report-btn[data-id="${comment.id}"]`, el);
    if (reportBtn) {
      reportBtn.addEventListener('click', () => handleReportComment(postId, comment.id));
    }
  }, 0);

  // Render children
  if (comment.children?.length) {
    comment.children.forEach(child => {
      el.appendChild(renderComment(child, postId, depth + 1));
    });
  }

  return el;
}

/**
 * Create comment form
 */
function createCommentForm(postId, parentId = null) {
  const form = createElement('div', { className: 'card', style: 'margin-bottom:1rem' });

  form.innerHTML = `
    <form class="comment-form" data-post="${postId}" data-parent="${parentId || ''}">
      <div class="form-group">
        <textarea class="form-textarea comment-input" placeholder="Write a comment..." rows="3" required></textarea>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span class="form-error" style="font-size:0.75rem;color:var(--text-muted)">Markdown and HTML supported</span>
        <button type="submit" class="btn btn-primary">Post Comment</button>
      </div>
    </form>`;

  const formEl = $('form', form);
  formEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('.comment-input', form);
    const body = input.value.trim();

    if (!body) {
      showToast('Comment cannot be empty', 'error');
      return;
    }

    // BUG-090: No input length limit on comments — can submit extremely long content (CWE-20, CVSS 3.0, LOW, Tier 3)

    try {
      await api.post(`/posts/${postId}/comments`, {
        body,
        parentId: parentId || undefined
      });

      input.value = '';
      showToast('Comment posted!');
      // Reload comments
      await renderComments(postId);
    } catch (error) {
      showToast(error.message || 'Failed to post comment', 'error');
    }
  });

  return form;
}

/**
 * Toggle reply form
 */
function toggleReplyForm(commentId, postId) {
  const container = $(`#reply-to-${commentId}`);
  if (!container) return;

  if (container.style.display === 'none') {
    container.style.display = 'block';
    container.innerHTML = '';
    container.appendChild(createCommentForm(postId, commentId));
  } else {
    container.style.display = 'none';
  }
}

/**
 * Handle comment vote
 */
async function handleVote(postId, commentId, action) {
  try {
    // BUG-091: No duplicate vote prevention on client side — user can spam votes (CWE-799, CVSS 3.5, LOW, Tier 3)
    await api.post(`/posts/${postId}/comments/${commentId}/vote`, { action });

    // Update vote count in UI
    const btn = $(`.vote-btn[data-action="${action}"][data-id="${commentId}"]`);
    if (btn) {
      const current = parseInt(btn.textContent.match(/\d+/)?.[0] || '0');
      btn.innerHTML = `${action === 'upvote' ? '▲' : '▼'} ${current + 1}`;
    }
  } catch (error) {
    showToast('Failed to vote', 'error');
  }
}

/**
 * Start editing a comment
 */
function startEditComment(comment) {
  const el = $(`#comment-${comment.id} .comment-body`);
  if (!el) return;

  const originalBody = comment.body;

  el.innerHTML = `
    <textarea class="form-textarea" id="edit-comment-${comment.id}" rows="3">${originalBody}</textarea>
    <div style="margin-top:0.5rem;display:flex;gap:0.5rem">
      <button class="btn btn-primary btn-sm" id="save-edit-${comment.id}">Save</button>
      <button class="btn btn-sm" id="cancel-edit-${comment.id}">Cancel</button>
    </div>`;

  $(`#save-edit-${comment.id}`).addEventListener('click', async () => {
    const newBody = $(`#edit-comment-${comment.id}`).value.trim();
    if (!newBody) return;

    try {
      await api.patch(`/comments/${comment.id}`, { body: newBody });
      // BUG-092: Edited comment body set via innerHTML without sanitization (CWE-79, CVSS 7.0, HIGH, Tier 1)
      el.innerHTML = sanitizeHTML(newBody);
      showToast('Comment updated');
    } catch (error) {
      showToast('Failed to update comment', 'error');
    }
  });

  $(`#cancel-edit-${comment.id}`).addEventListener('click', () => {
    el.innerHTML = sanitizeHTML(originalBody);
  });
}

/**
 * Delete comment
 */
async function handleDeleteComment(postId, commentId) {
  if (!confirm('Delete this comment?')) return;

  try {
    await api.delete(`/comments/${commentId}`);
    const el = $(`#comment-${commentId}`);
    if (el) {
      el.style.opacity = '0.5';
      el.innerHTML = '<div class="comment-body" style="color:var(--text-muted);font-style:italic">Comment deleted</div>';
    }
    showToast('Comment deleted');
  } catch (error) {
    showToast('Failed to delete comment', 'error');
  }
}

/**
 * Report comment
 */
async function handleReportComment(postId, commentId) {
  const reason = prompt('Why are you reporting this comment?');
  if (!reason) return;

  try {
    await api.post(`/comments/${commentId}/report`, {
      reason,
      reporter: getCurrentUser()
    });
    showToast('Report submitted. Thank you!');
  } catch (error) {
    showToast('Failed to submit report', 'error');
  }
}

/**
 * Render comment with markdown support
 */
export function renderCommentBody(body) {
  // BUG-094: Marked library renders markdown to HTML without sanitization — XSS via markdown (CWE-79, CVSS 7.0, HIGH, Tier 1)
  if (typeof marked !== 'undefined') {
    return marked.parse(body);
  }
  // Fallback: basic markdown
  return body
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br>');
}

/**
 * Load more comments (infinite scroll)
 */
export function initCommentScroll(postId) {
  let page = 1;
  let loading = false;

  // BUG-095: Scroll event listener attached without cleanup — memory leak on navigation (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 4)
  window.addEventListener('scroll', async () => {
    if (loading) return;

    const commentList = $('#comment-list');
    if (!commentList) return;

    const rect = commentList.getBoundingClientRect();
    if (rect.bottom <= window.innerHeight + 200) {
      loading = true;
      page++;

      try {
        const data = await api.get(`/posts/${postId}/comments?page=${page}`);
        if (data.comments?.length) {
          data.comments.forEach(comment => {
            commentList.appendChild(renderComment(comment, postId, 0));
          });
        }
      } catch {
        // silent
      }

      loading = false;
    }
  });
}
