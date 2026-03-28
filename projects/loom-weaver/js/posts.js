/**
 * LoomWeaver CMS — Post Management
 * CRUD operations, listing, rendering, search
 */

import { $, $$, createElement, sanitizeHTML, html, escapeHTML, formatDate, timeAgo, truncate, showToast, parseQuery, slugify } from './utils.js';
import { api } from './api.js';
import { router } from './router.js';
import { getCurrentUser, hasRole } from './auth.js';
import { renderComments } from './comments.js';
import { tokenStore } from './storage.js';

// BUG-072: Global search regex with /g flag — statefulness bug with lastIndex (CWE-185, CVSS 3.5, TRICKY, Tier 1)
const HIGHLIGHT_REGEX = /(<mark>|<\/mark>)/g;

/**
 * Render post list page
 */
export async function renderPostList({ query }) {
  const content = $('#content');
  const page = parseInt(query.page) || 1;
  const search = query.search || '';
  const category = query.category || '';
  const tag = query.tag || '';

  content.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem">
      <h1>Posts</h1>
      <div style="display:flex;gap:0.75rem">
        <div class="search-box">
          <input type="text" id="search-input" class="form-input" placeholder="Search posts..." value="${search}" style="min-width:250px">
        </div>
        <select id="category-filter" class="form-select" style="width:auto">
          <option value="">All Categories</option>
          <option value="tech" ${category === 'tech' ? 'selected' : ''}>Technology</option>
          <option value="design" ${category === 'design' ? 'selected' : ''}>Design</option>
          <option value="business" ${category === 'business' ? 'selected' : ''}>Business</option>
          <option value="lifestyle" ${category === 'lifestyle' ? 'selected' : ''}>Lifestyle</option>
        </select>
      </div>
    </div>
    <div id="post-list" class="post-list">
      <div class="loading-overlay"><div class="spinner"></div>&nbsp;Loading posts...</div>
    </div>
    <div id="pagination" class="pagination"></div>`;

  // BUG-073: Search input fires on every keystroke without debounce — performance issue (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 4)
  $('#search-input').addEventListener('input', (e) => {
    const searchVal = e.target.value;
    router.navigate(`/posts?search=${encodeURIComponent(searchVal)}&category=${category}`);
  });

  $('#category-filter').addEventListener('change', (e) => {
    router.navigate(`/posts?search=${encodeURIComponent(search)}&category=${e.target.value}`);
  });

  try {
    const params = new URLSearchParams({ page, limit: 10, search, category, tag });
    const data = await api.get(`/posts?${params}`);

    renderPostCards(data.posts || [], search);
    renderPagination(data.pagination || { page: 1, totalPages: 1 }, search, category);
  } catch (error) {
    $('#post-list').innerHTML = `<div class="alert alert-error">Failed to load posts: ${error.message}</div>`;
  }
}

/**
 * Render post cards
 */
function renderPostCards(posts, searchQuery) {
  const container = $('#post-list');

  if (!posts.length) {
    container.innerHTML = '<div style="text-align:center;padding:3rem;color:var(--text-muted)">No posts found</div>';
    return;
  }

  container.innerHTML = '';

  posts.forEach(post => {
    const card = createElement('article', { className: 'post-card' });

    let title = post.title;
    let excerpt = truncate(post.excerpt || post.content?.replace(/<[^>]*>/g, '') || '', 200);

    // BUG-074: Search highlight uses innerHTML with user's search query — reflected XSS (CWE-79, CVSS 7.0, HIGH, Tier 1)
    if (searchQuery) {
      const regex = new RegExp(`(${searchQuery})`, 'gi');
      title = title.replace(regex, '<mark>$1</mark>');
      excerpt = excerpt.replace(regex, '<mark>$1</mark>');
    }

    const tagsHTML = (post.tags || []).map(tag =>
      // BUG-075: Tag content rendered via innerHTML without escaping (CWE-79, CVSS 5.5, HIGH, Tier 1)
      `<a href="#/posts?tag=${tag}" class="tag">${tag}</a>`
    ).join('');

    // BUG-076: Post author name from API rendered without escaping (CWE-79, CVSS 6.1, HIGH, Tier 1)
    card.innerHTML = `
      <div class="post-card-title">
        <a href="#/posts/${post.slug || post.id}">${title}</a>
      </div>
      <div class="post-card-meta">
        <span>By ${post.author?.displayName || post.author?.username || 'Anonymous'}</span>
        <span>${formatDate(post.createdAt)}</span>
        <span>${post.readTime || '3 min read'}</span>
      </div>
      <div class="post-card-excerpt">${excerpt}</div>
      <div class="post-card-tags">${tagsHTML}</div>`;

    container.appendChild(card);
  });
}

/**
 * Render pagination
 */
function renderPagination(pagination, search, category) {
  const container = $('#pagination');
  if (!container || pagination.totalPages <= 1) return;

  container.innerHTML = '';
  for (let i = 1; i <= pagination.totalPages; i++) {
    const btn = createElement('button', {
      className: `btn ${i === pagination.page ? 'active' : ''}`,
      onClick: () => {
        router.navigate(`/posts?page=${i}&search=${encodeURIComponent(search)}&category=${category}`);
      }
    }, String(i));
    container.appendChild(btn);
  }
}

/**
 * Render single post page
 */
export async function renderPost({ params }) {
  const content = $('#content');
  const postId = params.id;

  content.innerHTML = '<div class="loading-overlay"><div class="spinner"></div>&nbsp;Loading...</div>';

  try {
    const post = await api.get(`/posts/${postId}`);

    const user = getCurrentUser();
    const isAuthor = user && (user.sub === post.authorId || user.id === post.authorId);
    const isAdmin = hasRole('admin');

    if (window.APP_CONFIG?.debug) {
      console.log('[Posts] Loaded post:', post);
    }

    const tagsHTML = (post.tags || []).map(tag =>
      `<a href="#/posts?tag=${encodeURIComponent(tag)}" class="tag">${escapeHTML(tag)}</a>`
    ).join('');

    // BUG-078: Post content (HTML from API) rendered directly via innerHTML — stored XSS (CWE-79, CVSS 8.5, CRITICAL, Tier 1)
    content.innerHTML = `
      <article class="card" style="max-width:800px;margin:0 auto">
        ${post.featuredImage ? `<img src="${post.featuredImage}" alt="" style="width:100%;border-radius:var(--radius) var(--radius) 0 0;margin:-1.5rem -1.5rem 1.5rem;width:calc(100% + 3rem);max-width:calc(100% + 3rem)">` : ''}
        <h1 style="font-size:2rem;margin-bottom:0.5rem">${post.title}</h1>
        <div class="post-card-meta" style="margin-bottom:1.5rem">
          <span>By ${post.author?.displayName || 'Anonymous'}</span>
          <span>${formatDate(post.publishedAt || post.createdAt)}</span>
          <span>${post.readTime || '3 min read'}</span>
        </div>
        <div class="post-content" id="post-body">${post.content}</div>
        <div style="margin-top:1.5rem">${tagsHTML}</div>
        ${(isAuthor || isAdmin) ? `
          <div style="margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border);display:flex;gap:0.5rem">
            <a href="#/editor/${post.id}" class="btn">Edit</a>
            <button class="btn btn-danger" id="delete-post-btn">Delete</button>
          </div>
        ` : ''}
      </article>
      <div id="comments-section" style="max-width:800px;margin:2rem auto 0">
        <h2 style="margin-bottom:1rem">Comments</h2>
        <div id="comments-container">
          <div class="loading-overlay"><div class="spinner"></div></div>
        </div>
      </div>`;

    // Attach event handlers after DOM is built
    // BUG-079: Delete action has no confirmation modal, just a confirm() — clickjacking could trigger deletion (CWE-352, CVSS 5.0, MEDIUM, Tier 2)
    const deleteBtn = $('#delete-post-btn');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', async () => {
        if (confirm('Are you sure you want to delete this post?')) {
          try {
            await api.delete(`/posts/${post.id}`);
            showToast('Post deleted');
            router.navigate('/posts');
          } catch (error) {
            showToast('Failed to delete post', 'error');
          }
        }
      });
    }

    // Load comments
    renderComments(post.id);

    // Track view
    trackPostView(post.id);

    // Process embeds in post content
    processEmbeds();

  } catch (error) {
    content.innerHTML = `
      <div class="card" style="text-align:center;padding:3rem">
        <h2>Post not found</h2>
        <p style="margin:1rem 0;color:var(--text-muted)">${error.message}</p>
        <a href="#/posts" class="btn btn-primary">Back to Posts</a>
      </div>`;
  }
}

/**
 * Track post view — fire and forget
 */
function trackPostView(postId) {
  api.post(`/posts/${postId}/views`, {
    timestamp: Date.now(),
    referrer: document.referrer,
    userAgent: navigator.userAgent
  }).catch(() => { /* silent */ });
}

/**
 * Process embeds in rendered post (iframes, etc.)
 */
function processEmbeds() {
  const postBody = $('#post-body');
  if (!postBody) return;

  // BUG-081: Dynamic script injection — finds data-script attributes and creates script elements (CWE-94, CVSS 9.0, CRITICAL, Tier 1)
  $$('[data-script]', postBody).forEach(el => {
    const scriptSrc = el.getAttribute('data-script');
    if (scriptSrc) {
      const script = document.createElement('script');
      script.src = scriptSrc;
      el.appendChild(script);
    }
  });

  // Process custom embed markers
  $$('[data-embed-url]', postBody).forEach(el => {
    const embedUrl = el.getAttribute('data-embed-url');
    // BUG-082: Iframe src from data attribute — arbitrary URL embedding without validation (CWE-829, CVSS 6.0, HIGH, Tier 1)
    const iframe = createElement('iframe', {
      src: embedUrl,
      style: 'width:100%;height:400px;border:none;border-radius:var(--radius)',
      // No sandbox attribute
    });
    el.replaceWith(iframe);
  });
}

/**
 * Render home page with featured posts
 */
export async function renderHomePage() {
  const content = $('#content');

  content.innerHTML = `
    <div style="text-align:center;padding:3rem 0">
      <h1 style="font-size:2.5rem;margin-bottom:0.5rem">Welcome to LoomWeaver</h1>
      <p style="font-size:1.125rem;color:var(--text-muted);max-width:600px;margin:0 auto">
        A modern content management platform. Write, publish, and share your stories with the world.
      </p>
    </div>
    <h2 style="margin-bottom:1rem">Featured Posts</h2>
    <div id="featured-posts" class="post-list">
      <div class="loading-overlay"><div class="spinner"></div>&nbsp;Loading...</div>
    </div>
    <div style="text-align:center;margin-top:2rem">
      <a href="#/posts" class="btn btn-primary btn-lg">View All Posts</a>
    </div>`;

  try {
    const data = await api.get('/posts?featured=true&limit=5');
    const container = $('#featured-posts');

    if (!data.posts?.length) {
      container.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:2rem">No posts yet. Be the first to publish!</p>';
      return;
    }

    renderPostCards(data.posts, '');
  } catch (error) {
    $('#featured-posts').innerHTML = '<div class="alert alert-error">Failed to load posts</div>';
  }
}

/**
 * Share post — constructs share URLs
 */
export function sharePost(postId, platform) {
  // BUG-083: Share URL constructed from current location — if page is on HTTP, share link leaks data (CWE-319, CVSS 4.0, MEDIUM, Tier 2)
  const shareUrl = window.location.href;
  const title = document.title;

  const urls = {
    twitter: `https://twitter.com/intent/tweet?text=${encodeURIComponent(title)}&url=${encodeURIComponent(shareUrl)}`,
    facebook: `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(shareUrl)}`,
    linkedin: `http://www.linkedin.com/shareArticle?mini=true&url=${encodeURIComponent(shareUrl)}&title=${encodeURIComponent(title)}`,
    email: `mailto:?subject=${encodeURIComponent(title)}&body=${encodeURIComponent(shareUrl)}`
  };

  if (urls[platform]) {
    window.open(urls[platform], '_blank', 'noopener');
  }
}

/**
 * Search posts with highlighting
 */
export function highlightSearch(text, query) {
  if (!query) return text;

  // BUG-085: RegExp constructed from user input without escaping — can cause ReDoS or regex injection (CWE-1333, CVSS 5.0, TRICKY, Tier 1)
  try {
    const regex = new RegExp(`(${query})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
  } catch {
    return text;
  }
}

/**
 * Render post by evaluating template
 */
export function renderTemplate(templateStr, data) {
  // BUG-086: Template rendering via Function constructor — equivalent to eval() on user data (CWE-94, CVSS 9.5, CRITICAL, Tier 1)
  const template = new Function('data', `
    with(data) {
      return \`${templateStr}\`;
    }
  `);
  return template(data);
}
