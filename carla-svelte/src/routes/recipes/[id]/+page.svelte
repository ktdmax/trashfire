<script lang="ts">
	// ============================================================
	// Recipe detail page — displays a single recipe with reviews,
	// related recipes, and actions (favorite, follow, edit, delete)
	// ============================================================

	import { enhance } from '$app/forms';
	import { page } from '$app/stores';
	import { invalidateAll } from '$app/navigation';
	import ReviewForm from '$lib/components/ReviewForm.svelte';
	import RecipeCard from '$lib/components/RecipeCard.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	let recipe = $derived(data.recipe);
	let reviews = $derived(data.reviews);
	let relatedRecipes = $derived(data.relatedRecipes);
	let isFavorited = $state(data.isFavorited);
	let isFollowing = $state(data.isFollowingAuthor);
	let isDeleting = $state(false);
	let showDeleteConfirm = $state(false);
	let editMode = $state(false);
	let activeTab = $state<'instructions' | 'reviews' | 'related'>('instructions');
	let servingMultiplier = $state(1);
	let shareTooltip = $state('');

	// Computed
	let totalTime = $derived((recipe?.prepTime || 0) + (recipe?.cookTime || 0));
	let adjustedIngredients = $derived(
		(recipe?.ingredients || []).map((ing: string) => {
			return ing.replace(/(\d+\.?\d*)/g, (match: string) => {
				const num = parseFloat(match) * servingMultiplier;
				return num % 1 === 0 ? num.toString() : num.toFixed(1);
			});
		})
	);

	let ratingDistribution = $derived(() => {
		const dist = [0, 0, 0, 0, 0];
		for (const review of reviews) {
			if (review.rating >= 1 && review.rating <= 5) {
				dist[review.rating - 1]++;
			}
		}
		return dist;
	});

	function formatDate(dateStr: string | Date): string {
		const date = new Date(dateStr);
		return date.toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'long',
			day: 'numeric'
		});
	}

	function getStarDisplay(rating: number): string {
		const full = Math.floor(rating);
		const half = rating - full >= 0.5 ? 1 : 0;
		const empty = 5 - full - half;
		return '★'.repeat(full) + (half ? '½' : '') + '☆'.repeat(empty);
	}

	async function handleShare() {
		const shareUrl = `${window.location.origin}/recipes/${recipe.slug}`;
		if (navigator.share) {
			try {
				await navigator.share({
					title: recipe.title,
					text: `Check out this recipe: ${recipe.title}`,
					url: shareUrl
				});
			} catch {
				// User cancelled share
			}
		} else {
			await navigator.clipboard.writeText(shareUrl);
			shareTooltip = 'Link copied!';
			setTimeout(() => shareTooltip = '', 2000);
		}
	}

	function confirmDelete() {
		showDeleteConfirm = true;
	}

	function cancelDelete() {
		showDeleteConfirm = false;
	}

	function adjustServings(delta: number) {
		const newVal = servingMultiplier + delta;
		if (newVal >= 0.5 && newVal <= 10) {
			servingMultiplier = newVal;
		}
	}

	function printRecipe() {
		window.print();
	}
</script>

<svelte:head>
	<title>{recipe?.title || 'Recipe'} | Carla Svelte</title>
	<meta name="description" content={recipe?.description?.slice(0, 160) || ''} />
	<meta property="og:title" content={recipe?.title || ''} />
	<meta property="og:description" content={recipe?.description?.slice(0, 160) || ''} />
	{#if recipe?.coverImage}
		<meta property="og:image" content={recipe.coverImage} />
	{/if}
</svelte:head>

{#if recipe}
	<article class="recipe-page">
		<!-- Hero Section -->
		<header class="recipe-hero">
			{#if recipe.coverImage}
				<div class="hero-image">
					<img src={recipe.coverImage} alt={recipe.title} />
					<div class="hero-overlay"></div>
				</div>
			{/if}

			<div class="hero-content">
				<div class="recipe-badges">
					{#if recipe.cuisine}
						<span class="badge cuisine">{recipe.cuisine}</span>
					{/if}
					{#if recipe.difficulty}
						<span class="badge difficulty {recipe.difficulty}">{recipe.difficulty}</span>
					{/if}
				</div>

				<h1>{recipe.title}</h1>

				<div class="recipe-meta">
					<span class="rating">
						{getStarDisplay(recipe.avg_rating || 0)}
						<span class="rating-text">
							{(recipe.avg_rating || 0).toFixed(1)} ({reviews.length} review{reviews.length !== 1 ? 's' : ''})
						</span>
					</span>

					<div class="meta-details">
						{#if recipe.prepTime}
							<span class="meta-item">Prep: {recipe.prepTime} min</span>
						{/if}
						{#if recipe.cookTime}
							<span class="meta-item">Cook: {recipe.cookTime} min</span>
						{/if}
						{#if totalTime > 0}
							<span class="meta-item total-time">Total: {totalTime} min</span>
						{/if}
						{#if recipe.servings}
							<span class="meta-item">Serves: {recipe.servings}</span>
						{/if}
					</div>

					<span class="view-count">{recipe.view_count || 0} views</span>
				</div>
			</div>
		</header>

		<!-- Author Bar -->
		<section class="author-bar">
			<a href="/cooks/{recipe.author_id}" class="author-info">
				{#if recipe.author_avatar}
					<img src={recipe.author_avatar} alt="" class="author-avatar" />
				{/if}
				<div>
					<span class="author-name">{recipe.author_display || recipe.author_name}</span>
					<span class="post-date">Published {formatDate(recipe.created_at)}</span>
				</div>
			</a>

			<div class="author-actions">
				{#if data.user && !data.isOwner}
					<form method="POST" action="?/toggleFavorite" use:enhance={() => {
						return async ({ result }) => {
							if (result.type === 'success') {
								isFavorited = !isFavorited;
							}
						};
					}}>
						<button type="submit" class="btn btn-outline" class:active={isFavorited}>
							{isFavorited ? '★ Saved' : '☆ Save'}
						</button>
					</form>
				{/if}

				<button class="btn btn-outline" onclick={handleShare}>
					Share
					{#if shareTooltip}
						<span class="tooltip">{shareTooltip}</span>
					{/if}
				</button>

				<button class="btn btn-outline" onclick={printRecipe}>
					Print
				</button>

				{#if data.isOwner || data.isAdmin}
					<button class="btn btn-outline" onclick={() => editMode = !editMode}>
						{editMode ? 'Cancel Edit' : 'Edit'}
					</button>
					<button class="btn btn-danger" onclick={confirmDelete}>
						Delete
					</button>
				{/if}
			</div>
		</section>

		<!-- Description -->
		{#if recipe.description}
			<section class="recipe-description">
				{@html recipe.description}
			</section>
		{/if}

		<!-- Tab Navigation -->
		<nav class="tab-nav">
			<button
				class="tab-btn"
				class:active={activeTab === 'instructions'}
				onclick={() => activeTab = 'instructions'}
			>
				Recipe
			</button>
			<button
				class="tab-btn"
				class:active={activeTab === 'reviews'}
				onclick={() => activeTab = 'reviews'}
			>
				Reviews ({reviews.length})
			</button>
			<button
				class="tab-btn"
				class:active={activeTab === 'related'}
				onclick={() => activeTab = 'related'}
			>
				Related
			</button>
		</nav>

		<!-- Instructions Tab -->
		{#if activeTab === 'instructions'}
			<div class="recipe-content">
				<!-- Ingredients Panel -->
				<aside class="ingredients-panel">
					<div class="ingredients-header">
						<h2>Ingredients</h2>
						<div class="serving-adjuster">
							<button class="adj-btn" onclick={() => adjustServings(-0.5)}>-</button>
							<span class="serving-count">{servingMultiplier}x</span>
							<button class="adj-btn" onclick={() => adjustServings(0.5)}>+</button>
						</div>
					</div>

					<ul class="ingredient-list">
						{#each adjustedIngredients as ingredient, i}
							<li>
								<label class="ingredient-item">
									<input type="checkbox" />
									<span>{ingredient}</span>
								</label>
							</li>
						{/each}
					</ul>
				</aside>

				<!-- Instructions Panel -->
				<div class="instructions-panel">
					<h2>Instructions</h2>
					<div class="instructions-content">
						{@html recipe.instructions}
					</div>
				</div>
			</div>
		{/if}

		<!-- Reviews Tab -->
		{#if activeTab === 'reviews'}
			<section class="reviews-section">
				<!-- Rating Summary -->
				<div class="rating-summary">
					<div class="rating-big">
						<span class="rating-number">{(recipe.avg_rating || 0).toFixed(1)}</span>
						<span class="rating-stars">{getStarDisplay(recipe.avg_rating || 0)}</span>
						<span class="rating-count">{reviews.length} review{reviews.length !== 1 ? 's' : ''}</span>
					</div>
				</div>

				<!-- Review Form -->
				<ReviewForm
					recipeId={recipe.id}
					recipeTitle={recipe.title}
					existingReview={data.userReview}
					isAuthenticated={!!data.user}
					currentUserId={data.user?.id}
				/>

				<!-- Review List -->
				<div class="review-list">
					{#each reviews as review}
						<div class="review-card">
							<div class="review-header">
								<a href="/cooks/{review.authorId}" class="reviewer-info">
									{#if review.authorAvatar}
										<img src={review.authorAvatar} alt="" class="reviewer-avatar" />
									{/if}
									<span class="reviewer-name">{review.authorDisplayName || review.authorName}</span>
								</a>
								<div class="review-meta">
									<span class="review-rating">{getStarDisplay(review.rating)}</span>
									<span class="review-date">{formatDate(review.createdAt)}</span>
								</div>
							</div>

							{#if review.comment}
								<div class="review-body">
									{@html review.comment}
								</div>
							{/if}

							{#if data.user && (review.authorId === data.user.id || data.isAdmin)}
								<form method="POST" action="?/deleteReview" use:enhance>
									<input type="hidden" name="reviewId" value={review.id} />
									<button type="submit" class="btn-text-danger">Delete</button>
								</form>
							{/if}
						</div>
					{/each}

					{#if reviews.length === 0}
						<p class="no-reviews">No reviews yet. Be the first to share your thoughts!</p>
					{/if}
				</div>
			</section>
		{/if}

		<!-- Related Recipes Tab -->
		{#if activeTab === 'related'}
			<section class="related-section">
				<h2>You Might Also Like</h2>
				{#if relatedRecipes && relatedRecipes.length > 0}
					<div class="related-grid">
						{#each relatedRecipes as related}
							<a href="/recipes/{related.slug}" class="related-card">
								{#if related.cover_image}
									<img src={related.cover_image} alt={related.title} />
								{/if}
								<div class="related-info">
									<h3>{related.title}</h3>
									<span class="related-rating">{getStarDisplay(related.avg_rating || 0)}</span>
									{#if related.cuisine}
										<span class="related-cuisine">{related.cuisine}</span>
									{/if}
								</div>
							</a>
						{/each}
					</div>
				{:else}
					<p class="no-related">No related recipes found.</p>
				{/if}
			</section>
		{/if}

		<!-- Delete Confirmation Modal -->
		{#if showDeleteConfirm}
			<div class="modal-overlay" onclick={cancelDelete}>
				<div class="modal" onclick={(e) => e.stopPropagation()}>
					<h3>Delete Recipe</h3>
					<p>Are you sure you want to delete "{recipe.title}"? This action cannot be undone.</p>
					<div class="modal-actions">
						<button class="btn btn-outline" onclick={cancelDelete}>Cancel</button>
						<form method="POST" action="?/delete" use:enhance={() => {
							isDeleting = true;
							return async () => {};
						}}>
							<button type="submit" class="btn btn-danger" disabled={isDeleting}>
								{isDeleting ? 'Deleting...' : 'Delete Recipe'}
							</button>
						</form>
					</div>
				</div>
			</div>
		{/if}
	</article>
{:else}
	<div class="not-found">
		<h1>Recipe Not Found</h1>
		<p>The recipe you're looking for doesn't exist or has been removed.</p>
		<a href="/recipes" class="btn btn-primary">Browse Recipes</a>
	</div>
{/if}

<style>
	.recipe-page {
		max-width: 1100px;
		margin: 0 auto;
		padding: 0 16px 48px;
	}

	/* Hero */
	.recipe-hero {
		position: relative;
		border-radius: 16px;
		overflow: hidden;
		margin-bottom: 24px;
		min-height: 300px;
		display: flex;
		align-items: flex-end;
	}

	.hero-image {
		position: absolute;
		inset: 0;
	}

	.hero-image img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}

	.hero-overlay {
		position: absolute;
		inset: 0;
		background: linear-gradient(transparent 30%, rgba(0, 0, 0, 0.7));
	}

	.hero-content {
		position: relative;
		z-index: 1;
		padding: 32px;
		color: white;
		width: 100%;
	}

	.hero-content h1 {
		font-size: 2.2rem;
		font-weight: 700;
		margin: 12px 0;
		line-height: 1.2;
		text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
	}

	.recipe-badges {
		display: flex;
		gap: 8px;
	}

	.badge {
		padding: 4px 12px;
		border-radius: 20px;
		font-size: 0.8rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.badge.cuisine { background: rgba(255, 255, 255, 0.2); backdrop-filter: blur(4px); }
	.badge.difficulty.easy { background: #c6f6d5; color: #22543d; }
	.badge.difficulty.medium { background: #fefcbf; color: #744210; }
	.badge.difficulty.hard { background: #fed7d7; color: #742a2a; }

	.recipe-meta {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 16px;
		font-size: 0.9rem;
	}

	.rating { color: #f59e0b; }
	.rating-text { color: rgba(255, 255, 255, 0.8); margin-left: 4px; }

	.meta-details {
		display: flex;
		gap: 12px;
	}

	.meta-item {
		opacity: 0.9;
	}

	.total-time {
		font-weight: 600;
	}

	.view-count {
		opacity: 0.7;
		font-size: 0.85rem;
	}

	/* Author Bar */
	.author-bar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 16px 0;
		border-bottom: 1px solid #e2e8f0;
		margin-bottom: 24px;
		flex-wrap: wrap;
		gap: 12px;
	}

	.author-info {
		display: flex;
		align-items: center;
		gap: 12px;
		text-decoration: none;
		color: inherit;
	}

	.author-avatar {
		width: 48px;
		height: 48px;
		border-radius: 50%;
		object-fit: cover;
	}

	.author-name {
		font-weight: 600;
		display: block;
		color: #1e293b;
	}

	.post-date {
		font-size: 0.85rem;
		color: #64748b;
	}

	.author-actions {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
	}

	/* Buttons */
	.btn {
		padding: 8px 16px;
		border-radius: 8px;
		font-size: 0.9rem;
		font-weight: 500;
		cursor: pointer;
		transition: all 0.2s;
		border: none;
	}

	.btn-outline {
		background: white;
		border: 1px solid #d1d5db;
		color: #374151;
		position: relative;
	}

	.btn-outline:hover { background: #f3f4f6; }
	.btn-outline.active { background: #fef3c7; border-color: #f59e0b; color: #92400e; }

	.btn-primary {
		background: #3b82f6;
		color: white;
	}

	.btn-primary:hover { background: #2563eb; }

	.btn-danger {
		background: #ef4444;
		color: white;
	}

	.btn-danger:hover { background: #dc2626; }

	.btn-text-danger {
		background: none;
		border: none;
		color: #ef4444;
		font-size: 0.8rem;
		cursor: pointer;
		padding: 4px 8px;
	}

	.btn-text-danger:hover { text-decoration: underline; }

	.tooltip {
		position: absolute;
		bottom: -28px;
		left: 50%;
		transform: translateX(-50%);
		background: #1e293b;
		color: white;
		padding: 4px 8px;
		border-radius: 4px;
		font-size: 0.75rem;
		white-space: nowrap;
	}

	/* Description */
	.recipe-description {
		font-size: 1rem;
		line-height: 1.7;
		color: #475569;
		margin-bottom: 24px;
		padding: 16px;
		background: #f8fafc;
		border-radius: 12px;
	}

	/* Tabs */
	.tab-nav {
		display: flex;
		border-bottom: 2px solid #e2e8f0;
		margin-bottom: 24px;
		gap: 4px;
	}

	.tab-btn {
		padding: 12px 20px;
		background: none;
		border: none;
		border-bottom: 2px solid transparent;
		margin-bottom: -2px;
		font-size: 0.95rem;
		font-weight: 500;
		color: #64748b;
		cursor: pointer;
		transition: all 0.2s;
	}

	.tab-btn:hover { color: #1e293b; }
	.tab-btn.active { color: #3b82f6; border-bottom-color: #3b82f6; }

	/* Recipe Content */
	.recipe-content {
		display: grid;
		grid-template-columns: 1fr 2fr;
		gap: 32px;
	}

	/* Ingredients */
	.ingredients-panel {
		background: #f8fafc;
		border-radius: 12px;
		padding: 24px;
		height: fit-content;
		position: sticky;
		top: 16px;
	}

	.ingredients-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 16px;
	}

	.ingredients-header h2 {
		margin: 0;
		font-size: 1.2rem;
	}

	.serving-adjuster {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.adj-btn {
		width: 28px;
		height: 28px;
		border-radius: 50%;
		border: 1px solid #d1d5db;
		background: white;
		cursor: pointer;
		font-size: 1rem;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.adj-btn:hover { background: #f3f4f6; }

	.serving-count {
		font-weight: 600;
		min-width: 32px;
		text-align: center;
	}

	.ingredient-list {
		list-style: none;
		padding: 0;
		margin: 0;
	}

	.ingredient-list li {
		border-bottom: 1px solid #e2e8f0;
	}

	.ingredient-list li:last-child {
		border-bottom: none;
	}

	.ingredient-item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 0;
		cursor: pointer;
		font-size: 0.95rem;
	}

	.ingredient-item input[type="checkbox"] {
		accent-color: #3b82f6;
	}

	.ingredient-item:has(input:checked) span {
		text-decoration: line-through;
		opacity: 0.5;
	}

	/* Instructions */
	.instructions-panel h2 {
		font-size: 1.2rem;
		margin: 0 0 16px;
	}

	.instructions-content {
		line-height: 1.8;
		font-size: 1rem;
		color: #374151;
	}

	.instructions-content :global(h2),
	.instructions-content :global(h3) {
		margin-top: 24px;
	}

	.instructions-content :global(ol) {
		padding-left: 24px;
	}

	.instructions-content :global(li) {
		margin-bottom: 12px;
	}

	/* Reviews */
	.reviews-section {
		max-width: 800px;
	}

	.rating-summary {
		text-align: center;
		padding: 24px;
		background: #f8fafc;
		border-radius: 12px;
		margin-bottom: 24px;
	}

	.rating-number {
		font-size: 3rem;
		font-weight: 700;
		color: #1e293b;
		display: block;
	}

	.rating-stars {
		font-size: 1.5rem;
		color: #f59e0b;
		display: block;
		margin: 4px 0;
	}

	.rating-count {
		color: #64748b;
		font-size: 0.9rem;
	}

	.review-list {
		margin-top: 24px;
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.review-card {
		padding: 20px;
		border: 1px solid #e2e8f0;
		border-radius: 12px;
		background: white;
	}

	.review-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 12px;
	}

	.reviewer-info {
		display: flex;
		align-items: center;
		gap: 8px;
		text-decoration: none;
		color: inherit;
	}

	.reviewer-avatar {
		width: 32px;
		height: 32px;
		border-radius: 50%;
		object-fit: cover;
	}

	.reviewer-name {
		font-weight: 600;
		font-size: 0.95rem;
	}

	.review-meta {
		text-align: right;
	}

	.review-rating {
		color: #f59e0b;
		display: block;
	}

	.review-date {
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.review-body {
		line-height: 1.6;
		color: #475569;
	}

	.no-reviews {
		text-align: center;
		color: #94a3b8;
		padding: 32px;
	}

	/* Related */
	.related-section h2 {
		font-size: 1.3rem;
		margin-bottom: 16px;
	}

	.related-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
		gap: 16px;
	}

	.related-card {
		border: 1px solid #e2e8f0;
		border-radius: 12px;
		overflow: hidden;
		text-decoration: none;
		color: inherit;
		transition: transform 0.2s, box-shadow 0.2s;
	}

	.related-card:hover {
		transform: translateY(-2px);
		box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
	}

	.related-card img {
		width: 100%;
		aspect-ratio: 16 / 10;
		object-fit: cover;
	}

	.related-info {
		padding: 12px;
	}

	.related-info h3 {
		font-size: 1rem;
		margin: 0 0 4px;
	}

	.related-rating {
		color: #f59e0b;
		font-size: 0.85rem;
	}

	.related-cuisine {
		font-size: 0.8rem;
		color: #64748b;
		margin-left: 8px;
	}

	.no-related {
		text-align: center;
		color: #94a3b8;
		padding: 32px;
	}

	/* Delete Modal */
	.modal-overlay {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.5);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 100;
	}

	.modal {
		background: white;
		border-radius: 16px;
		padding: 32px;
		max-width: 440px;
		width: 90%;
		box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
	}

	.modal h3 {
		margin: 0 0 12px;
		font-size: 1.2rem;
	}

	.modal p {
		color: #64748b;
		line-height: 1.5;
		margin-bottom: 24px;
	}

	.modal-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
	}

	/* Not Found */
	.not-found {
		text-align: center;
		padding: 80px 16px;
	}

	.not-found h1 {
		font-size: 2rem;
		margin-bottom: 12px;
	}

	.not-found p {
		color: #64748b;
		margin-bottom: 24px;
	}

	/* Responsive */
	@media (max-width: 768px) {
		.recipe-content {
			grid-template-columns: 1fr;
		}

		.ingredients-panel {
			position: static;
		}

		.hero-content h1 {
			font-size: 1.6rem;
		}

		.author-bar {
			flex-direction: column;
			align-items: flex-start;
		}
	}

	/* Print styles */
	@media print {
		.author-actions,
		.tab-nav,
		.review-form-container,
		.related-section,
		.modal-overlay {
			display: none !important;
		}

		.recipe-content {
			grid-template-columns: 1fr;
		}

		.ingredients-panel {
			position: static;
			break-inside: avoid;
		}
	}
</style>
