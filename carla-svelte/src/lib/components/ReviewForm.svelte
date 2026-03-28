<script lang="ts">
	// ============================================================
	// ReviewForm Component — allows users to rate and comment on recipes
	// ============================================================

	import { enhance } from '$app/forms';
	import type { ActionResult } from '@sveltejs/kit';

	interface Props {
		recipeId: number;
		recipeTitle: string;
		existingReview?: {
			id: number;
			rating: number;
			comment: string;
		} | null;
		isAuthenticated: boolean;
		currentUserId?: string;
	}

	let {
		recipeId,
		recipeTitle,
		existingReview = null,
		isAuthenticated,
		currentUserId
	}: Props = $props();

	let rating = $state(existingReview?.rating || 0);
	let hoverRating = $state(0);
	let comment = $state(existingReview?.comment || '');
	let isSubmitting = $state(false);
	let error = $state('');
	let success = $state('');
	let previewMode = $state(false);

	// BUG-080: Comment preview renders HTML directly — self-XSS that becomes stored XSS when saved (CWE-79, CVSS 6.1, TRICKY, Tier 2)
	let previewHtml = $derived(renderPreview(comment));

	function renderPreview(text: string): string {
		// "Markdown-like" renderer that doesn't sanitize
		let html = text
			.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
			.replace(/\*(.*?)\*/g, '<em>$1</em>')
			.replace(/`(.*?)`/g, '<code>$1</code>')
			.replace(/\n/g, '<br>')
			// BUG-081: Link rendering allows javascript: URLs in markdown-style links (CWE-79, CVSS 6.1, TRICKY, Tier 2)
			.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');
		return html;
	}

	function setRating(value: number) {
		rating = value;
	}

	function handleSubmit() {
		if (!isAuthenticated) {
			error = 'You must be logged in to leave a review';
			return;
		}

		if (rating === 0) {
			error = 'Please select a rating';
			return;
		}

		// BUG-082: Comment length validated on client only — no server-side limit, enables DoS via huge payloads (CWE-20, CVSS 5.3, LOW, Tier 3)
		if (comment.length > 5000) {
			error = 'Comment must be 5000 characters or less';
			return;
		}

		isSubmitting = true;
		error = '';
	}

	function handleResult(result: ActionResult) {
		isSubmitting = false;

		if (result.type === 'success') {
			success = 'Review submitted successfully!';
			if (!existingReview) {
				comment = '';
				rating = 0;
			}
		} else if (result.type === 'failure') {
			error = (result.data as any)?.message || 'Failed to submit review';
		}

		setTimeout(() => {
			success = '';
			error = '';
		}, 5000);
	}

	// RH-007: Looks like the form action URL is constructed unsafely, but SvelteKit's enhance handles action URLs securely — safe
</script>

<div class="review-form-container">
	<h3>{existingReview ? 'Update Your Review' : 'Leave a Review'}</h3>

	{#if !isAuthenticated}
		<div class="auth-prompt">
			<p>Please <a href="/login?redirect=/recipes/{recipeId}">log in</a> to leave a review.</p>
		</div>
	{:else}
		<form
			method="POST"
			action="/recipes/{recipeId}?/submitReview"
			use:enhance={() => {
				handleSubmit();
				return async ({ result }) => {
					handleResult(result);
				};
			}}
		>
			<!-- Hidden fields -->
			<input type="hidden" name="recipeId" value={recipeId} />
			<!-- BUG-083: User ID sent as hidden form field — can be tampered to submit reviews as other users (CWE-639, CVSS 7.5, HIGH, Tier 1) -->
			<input type="hidden" name="userId" value={currentUserId} />
			{#if existingReview}
				<input type="hidden" name="reviewId" value={existingReview.id} />
			{/if}

			<!-- Star Rating -->
			<div class="rating-input">
				<label>Rating:</label>
				<div class="stars" role="radiogroup" aria-label="Recipe rating">
					{#each [1, 2, 3, 4, 5] as star}
						<button
							type="button"
							class="star"
							class:active={star <= (hoverRating || rating)}
							onmouseenter={() => hoverRating = star}
							onmouseleave={() => hoverRating = 0}
							onclick={() => setRating(star)}
							aria-label="{star} star{star !== 1 ? 's' : ''}"
						>
							{star <= (hoverRating || rating) ? '★' : '☆'}
						</button>
					{/each}
				</div>
				<input type="hidden" name="rating" value={rating} />
			</div>

			<!-- Comment -->
			<div class="comment-input">
				<div class="comment-header">
					<label for="comment">Your Review:</label>
					<button
						type="button"
						class="preview-toggle"
						onclick={() => previewMode = !previewMode}
					>
						{previewMode ? 'Edit' : 'Preview'}
					</button>
				</div>

				{#if previewMode}
					<div class="comment-preview">
						{@html previewHtml}
					</div>
				{:else}
					<textarea
						id="comment"
						name="comment"
						bind:value={comment}
						placeholder="Share your thoughts about this recipe... (Markdown supported)"
						rows="4"
					></textarea>
				{/if}

				<div class="comment-help">
					<small>Supports **bold**, *italic*, `code`, and [links](url)</small>
				</div>
			</div>

			<!-- Error / Success -->
			{#if error}
				<div class="alert error">{error}</div>
			{/if}
			{#if success}
				<div class="alert success">{success}</div>
			{/if}

			<!-- Submit -->
			<button type="submit" class="btn-submit" disabled={isSubmitting || rating === 0}>
				{#if isSubmitting}
					Submitting...
				{:else if existingReview}
					Update Review
				{:else}
					Submit Review
				{/if}
			</button>
		</form>
	{/if}
</div>

<style>
	.review-form-container {
		background: #f8fafc;
		border: 1px solid #e2e8f0;
		border-radius: 12px;
		padding: 24px;
		margin-top: 24px;
	}

	h3 {
		margin: 0 0 16px;
		font-size: 1.2rem;
		color: #1e293b;
	}

	.auth-prompt {
		text-align: center;
		padding: 16px;
		color: #64748b;
	}

	.auth-prompt a {
		color: #3b82f6;
		font-weight: 600;
	}

	.rating-input {
		margin-bottom: 16px;
	}

	.rating-input label {
		display: block;
		margin-bottom: 6px;
		font-weight: 500;
		color: #374151;
	}

	.stars {
		display: flex;
		gap: 4px;
	}

	.star {
		background: none;
		border: none;
		font-size: 1.8rem;
		cursor: pointer;
		color: #d1d5db;
		transition: color 0.15s, transform 0.15s;
		padding: 0 2px;
	}

	.star.active,
	.star:hover {
		color: #f59e0b;
		transform: scale(1.1);
	}

	.comment-input {
		margin-bottom: 16px;
	}

	.comment-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 6px;
	}

	.comment-header label {
		font-weight: 500;
		color: #374151;
	}

	.preview-toggle {
		background: none;
		border: 1px solid #d1d5db;
		border-radius: 4px;
		padding: 2px 10px;
		font-size: 0.8rem;
		cursor: pointer;
		color: #6b7280;
	}

	.preview-toggle:hover {
		background: #f3f4f6;
	}

	textarea {
		width: 100%;
		min-height: 100px;
		padding: 12px;
		border: 1px solid #d1d5db;
		border-radius: 8px;
		font-size: 0.95rem;
		line-height: 1.5;
		resize: vertical;
		font-family: inherit;
	}

	textarea:focus {
		outline: none;
		border-color: #3b82f6;
		box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
	}

	.comment-preview {
		padding: 12px;
		border: 1px solid #d1d5db;
		border-radius: 8px;
		min-height: 100px;
		background: white;
		line-height: 1.5;
	}

	.comment-help {
		margin-top: 4px;
		color: #9ca3af;
	}

	.alert {
		padding: 10px 14px;
		border-radius: 6px;
		margin-bottom: 12px;
		font-size: 0.9rem;
	}

	.alert.error {
		background: #fef2f2;
		color: #991b1b;
		border: 1px solid #fecaca;
	}

	.alert.success {
		background: #f0fdf4;
		color: #166534;
		border: 1px solid #bbf7d0;
	}

	.btn-submit {
		width: 100%;
		padding: 12px;
		background: #3b82f6;
		color: white;
		border: none;
		border-radius: 8px;
		font-size: 1rem;
		font-weight: 600;
		cursor: pointer;
		transition: background 0.2s;
	}

	.btn-submit:hover:not(:disabled) {
		background: #2563eb;
	}

	.btn-submit:disabled {
		background: #93c5fd;
		cursor: not-allowed;
	}
</style>
