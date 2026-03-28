<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Erusev\Parsedown;

class ReputationService
{
    /**
     * Get reputation data for a user.
     */
    public function getReputation(int $userId): array
    {
        $user = User::findOrFail($userId);

        $reviews = DB::table('reviews')
            ->join('users', 'reviews.reviewer_id', '=', 'users.id')
            ->where('reviews.reviewed_user_id', $userId)
            ->select(
                'reviews.*',
                'users.name as reviewer_name',
                'users.email as reviewer_email'
            )
            ->orderBy('reviews.created_at', 'desc')
            ->get();

        $stats = [
            'average_rating' => $reviews->avg('rating') ?? 0,
            'total_reviews' => $reviews->count(),
            'rating_distribution' => [
                5 => $reviews->where('rating', 5)->count(),
                4 => $reviews->where('rating', 4)->count(),
                3 => $reviews->where('rating', 3)->count(),
                2 => $reviews->where('rating', 2)->count(),
                1 => $reviews->where('rating', 1)->count(),
            ],
            'completed_sales' => DB::table('auctions')
                ->where('seller_id', $userId)
                ->where('status', 'completed')
                ->count(),
            'completed_purchases' => DB::table('auctions')
                ->where('winner_id', $userId)
                ->where('status', 'completed')
                ->count(),
        ];

        return [
            'user_id' => $userId,
            'reputation_score' => $user->reputation_score,
            'stats' => $stats,
            'reviews' => $reviews->toArray(),
        ];
    }

    /**
     * Submit a review for a user.
     */
    public function submitReview(int $reviewedUserId, int $reviewerId, int $rating, string $comment = ''): array
    {
        // BUG-0110: No check that reviewer and reviewed user had a transaction — anyone can review anyone (CWE-862, CVSS 5.3, TRICKY, Tier 3)

        // BUG-0111: Rating not validated — can submit rating of 0, -1, or 999, skewing reputation calculations (CWE-20, CVSS 5.3, MEDIUM, Tier 2)

        // BUG-0112: No duplicate review prevention — user can submit unlimited reviews to inflate/deflate reputation (CWE-799, CVSS 6.5, TRICKY, Tier 3)

        // BUG-0113: Comment stored and later rendered without sanitization — stored XSS via Parsedown rendering (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
        $parsedComment = (new Parsedown())->text($comment);

        DB::table('reviews')->insert([
            'reviewed_user_id' => $reviewedUserId,
            'reviewer_id' => $reviewerId,
            'rating' => $rating,
            'comment' => $comment,
            'comment_html' => $parsedComment,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Recalculate reputation
        $user = User::findOrFail($reviewedUserId);
        $user->recalculateReputation();

        // BUG-0114: Cache key predictable and not user-scoped — cache poisoning if attacker can predict key pattern (CWE-345, CVSS 3.7, BEST_PRACTICE, Tier 4)
        Cache::forget("reputation_{$reviewedUserId}");

        Log::info("Review submitted for user {$reviewedUserId} by {$reviewerId}: rating {$rating}");

        return [
            'success' => true,
            'new_reputation' => $user->fresh()->reputation_score,
        ];
    }

    /**
     * Get top sellers by reputation.
     */
    public function getTopSellers(int $limit = 20): array
    {
        return DB::table('users')
            ->where('role', 'seller')
            ->where('status', 'active')
            ->orderBy('reputation_score', 'desc')
            ->limit($limit)
            ->select('id', 'name', 'reputation_score', 'created_at')
            ->get()
            ->toArray();
    }

    /**
     * Flag suspicious reputation activity.
     */
    public function detectFraud(int $userId): array
    {
        $flags = [];

        // Check for self-reviews (same IP)
        $selfReviews = DB::table('reviews as r1')
            ->join('reviews as r2', function ($join) {
                $join->on('r1.reviewed_user_id', '=', 'r2.reviewer_id')
                    ->on('r1.reviewer_id', '=', 'r2.reviewed_user_id');
            })
            ->where('r1.reviewed_user_id', $userId)
            ->count();

        if ($selfReviews > 0) {
            $flags[] = 'reciprocal_reviews';
        }

        // Check for burst of reviews in short time
        $recentReviews = DB::table('reviews')
            ->where('reviewed_user_id', $userId)
            ->where('created_at', '>=', now()->subHours(24))
            ->count();

        if ($recentReviews > 10) {
            $flags[] = 'review_burst';
        }

        // Check for reviews from accounts created same day
        $newAccountReviews = DB::table('reviews')
            ->join('users', 'reviews.reviewer_id', '=', 'users.id')
            ->where('reviews.reviewed_user_id', $userId)
            ->whereRaw('DATE(users.created_at) = DATE(reviews.created_at)')
            ->count();

        if ($newAccountReviews > 3) {
            $flags[] = 'new_account_reviews';
        }

        return [
            'user_id' => $userId,
            'flags' => $flags,
            'suspicious' => count($flags) > 0,
        ];
    }

    /**
     * Generate a reputation badge based on score.
     */
    public function getBadge(float $score): string
    {
        return match (true) {
            $score >= 4.8 => 'platinum',
            $score >= 4.0 => 'gold',
            $score >= 3.0 => 'silver',
            $score >= 2.0 => 'bronze',
            default => 'none',
        };
    }

    /**
     * Bulk update reputation scores (cron job).
     */
    public function recalculateAll(): int
    {
        $users = User::where('role', 'seller')->get();
        $updated = 0;

        foreach ($users as $user) {
            $user->recalculateReputation();
            $updated++;
        }

        Log::info("Reputation recalculated for {$updated} sellers");

        return $updated;
    }
}
