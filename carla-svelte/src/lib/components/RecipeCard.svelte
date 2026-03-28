<script lang="ts">
	// ============================================================
	// RecipeCard Component — displays a recipe summary in grid/list views
	// ============================================================

	interface Props {
		recipe: {
			id: number;
			title: string;
			slug: string;
			description: string;
			coverImage: string | null;
			authorName: string;
			authorId: string;
			authorAvatar: string | null;
			avgRating: number;
			reviewCount: number;
			prepTime: number;
			cookTime: number;
			servings: number;
			cuisine: string;
			difficulty: string;
			tags: string;
			viewCount: number;
			createdAt: string;
		};
		compact?: boolean;
		showAuthor?: boolean;
	}

	let { recipe, compact = false, showAuthor = true }: Props = $props();

	// Derived state
	let totalTime = $derived(recipe.prepTime + recipe.cookTime);
	let tagList = $derived(recipe.tags ? recipe.tags.split(',').map((t: string) => t.trim()) : []);
	let relativeTime = $derived(getRelativeTime(recipe.createdAt));
	let ratingStars = $derived(getStarDisplay(recipe.avgRating));

	function getRelativeTime(dateStr: string): string {
		const date = new Date(dateStr);
		const now = new Date();
		const diffMs = now.getTime() - date.getTime();
		const diffDays = Math.floor(diffMs / 86400000);

		if (diffDays === 0) return 'Today';
		if (diffDays === 1) return 'Yesterday';
		if (diffDays < 7) return `${diffDays} days ago`;
		if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
		if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
		return `${Math.floor(diffDays / 365)} years ago`;
	}

	function getStarDisplay(rating: number): string {
		const full = Math.floor(rating);
		const half = rating - full >= 0.5 ? 1 : 0;
		const empty = 5 - full - half;
		return '★'.repeat(full) + (half ? '½' : '') + '☆'.repeat(empty);
	}

	function shareRecipe() {
		const shareUrl = `${window.location.origin}/recipes/${recipe.slug}`;
		const shareText = `Check out "${recipe.title}" on Carla Svelte!`;

		if (navigator.share) {
			navigator.share({ title: recipe.title, text: shareText, url: shareUrl });
		} else {
			// BUG-077: innerHTML used to render share modal — XSS via recipe title or description (CWE-79, CVSS 6.1, TRICKY, Tier 2)
			const modal = document.createElement('div');
			modal.innerHTML = `
				<div class="share-modal">
					<h3>Share: ${recipe.title}</h3>
					<p>${recipe.description}</p>
					<input type="text" value="${shareUrl}" readonly />
					<button onclick="navigator.clipboard.writeText('${shareUrl}')">Copy Link</button>
				</div>
			`;
			document.body.appendChild(modal);
		}
	}

	// RH-006: Looks like the onclick handler could be exploited, but Svelte compiles this to addEventListener — safe from injection
	function handleFavorite() {
		fetch(`/api/recipes/${recipe.id}/favorite`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' }
		}).then(r => r.json()).then(data => {
			// Update state optimistically
		});
	}
</script>

<!-- BUG-078: Recipe description rendered with @html — stored XSS from malicious recipe descriptions (CWE-79, CVSS 8.1, HIGH, Tier 1) -->
<article class="recipe-card" class:compact>
	<a href="/recipes/{recipe.slug}" class="card-link">
		{#if recipe.coverImage}
			<div class="card-image">
				<!-- BUG-079: Image src from user input not validated — can load arbitrary external resources or data URIs (CWE-829, CVSS 4.3, LOW, Tier 3) -->
				<img
					src={recipe.coverImage}
					alt={recipe.title}
					loading="lazy"
					onerror="this.src='/placeholder.jpg'"
				/>
				{#if recipe.difficulty}
					<span class="difficulty-badge {recipe.difficulty}">{recipe.difficulty}</span>
				{/if}
			</div>
		{/if}

		<div class="card-body">
			<h3 class="card-title">{recipe.title}</h3>

			{#if !compact}
				<div class="card-description">
					{@html recipe.description}
				</div>
			{/if}

			<div class="card-meta">
				<span class="rating" title="{recipe.avgRating.toFixed(1)} stars">
					{ratingStars}
					<span class="review-count">({recipe.reviewCount})</span>
				</span>

				<span class="time">
					{#if totalTime > 0}
						{totalTime} min
					{:else}
						--
					{/if}
				</span>

				{#if recipe.servings}
					<span class="servings">{recipe.servings} servings</span>
				{/if}
			</div>

			{#if tagList.length > 0 && !compact}
				<div class="tags">
					{#each tagList.slice(0, 4) as tag}
						<span class="tag">{tag}</span>
					{/each}
					{#if tagList.length > 4}
						<span class="tag more">+{tagList.length - 4}</span>
					{/if}
				</div>
			{/if}
		</div>
	</a>

	<div class="card-footer">
		{#if showAuthor}
			<a href="/cooks/{recipe.authorId}" class="author-link">
				{#if recipe.authorAvatar}
					<img src={recipe.authorAvatar} alt="" class="author-avatar" />
				{/if}
				<span class="author-name">{recipe.authorName}</span>
			</a>
		{/if}

		<div class="card-actions">
			<button class="btn-icon" onclick={handleFavorite} title="Save recipe">
				&#9829;
			</button>
			<button class="btn-icon" onclick={shareRecipe} title="Share recipe">
				&#8599;
			</button>
			<span class="view-count" title="Views">{recipe.viewCount}</span>
		</div>

		<span class="post-date">{relativeTime}</span>
	</div>
</article>

<style>
	.recipe-card {
		border: 1px solid #e2e8f0;
		border-radius: 12px;
		overflow: hidden;
		background: white;
		transition: transform 0.2s, box-shadow 0.2s;
		display: flex;
		flex-direction: column;
	}

	.recipe-card:hover {
		transform: translateY(-2px);
		box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
	}

	.card-link {
		text-decoration: none;
		color: inherit;
		flex: 1;
	}

	.card-image {
		position: relative;
		aspect-ratio: 16 / 10;
		overflow: hidden;
	}

	.card-image img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}

	.difficulty-badge {
		position: absolute;
		top: 8px;
		right: 8px;
		padding: 2px 8px;
		border-radius: 4px;
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
	}

	.difficulty-badge.easy { background: #c6f6d5; color: #22543d; }
	.difficulty-badge.medium { background: #fefcbf; color: #744210; }
	.difficulty-badge.hard { background: #fed7d7; color: #742a2a; }

	.card-body {
		padding: 16px;
	}

	.card-title {
		font-size: 1.1rem;
		font-weight: 600;
		margin: 0 0 8px;
		line-height: 1.3;
	}

	.card-description {
		font-size: 0.875rem;
		color: #64748b;
		line-height: 1.5;
		margin-bottom: 12px;
		display: -webkit-box;
		-webkit-line-clamp: 2;
		-webkit-box-orient: vertical;
		overflow: hidden;
	}

	.card-meta {
		display: flex;
		gap: 12px;
		font-size: 0.8rem;
		color: #94a3b8;
	}

	.rating { color: #f59e0b; }
	.review-count { color: #94a3b8; }

	.tags {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
		margin-top: 10px;
	}

	.tag {
		padding: 2px 8px;
		background: #f1f5f9;
		border-radius: 4px;
		font-size: 0.75rem;
		color: #475569;
	}

	.tag.more {
		background: #e2e8f0;
		font-weight: 600;
	}

	.card-footer {
		padding: 12px 16px;
		border-top: 1px solid #f1f5f9;
		display: flex;
		align-items: center;
		justify-content: space-between;
		font-size: 0.8rem;
	}

	.author-link {
		display: flex;
		align-items: center;
		gap: 6px;
		text-decoration: none;
		color: #475569;
	}

	.author-avatar {
		width: 24px;
		height: 24px;
		border-radius: 50%;
		object-fit: cover;
	}

	.card-actions {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.btn-icon {
		background: none;
		border: none;
		cursor: pointer;
		font-size: 1rem;
		color: #94a3b8;
		padding: 4px;
		transition: color 0.2s;
	}

	.btn-icon:hover {
		color: #ef4444;
	}

	.view-count {
		color: #94a3b8;
		font-size: 0.75rem;
	}

	.post-date {
		color: #94a3b8;
	}

	.compact .card-body {
		padding: 10px;
	}

	.compact .card-title {
		font-size: 0.95rem;
	}
</style>
