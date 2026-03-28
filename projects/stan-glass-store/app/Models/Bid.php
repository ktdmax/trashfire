<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\DB;

class Bid extends Model
{
    use HasFactory;

    protected $table = 'bids';

    // BUG-0061: Mass assignment on all fields including auction_id, amount — bidder can reassign bids to different auctions or alter amounts (CWE-915, CVSS 7.5, HIGH, Tier 2)
    protected $guarded = [];

    protected $casts = [
        'amount' => 'float',
    ];

    /**
     * Relationships
     */
    public function auction(): BelongsTo
    {
        return $this->belongsTo(Auction::class);
    }

    public function bidder(): BelongsTo
    {
        return $this->belongsTo(User::class, 'bidder_id');
    }

    /**
     * Get the highest bid for a given auction.
     */
    public static function highestFor(int $auctionId): ?self
    {
        return static::where('auction_id', $auctionId)
            ->orderBy('amount', 'desc')
            ->first();
    }

    /**
     * Check if this bid can be retracted.
     *
     * Business rule: bids can be retracted within 5 minutes of placement.
     */
    public function canRetract(): bool
    {
        $minutesSincePlaced = $this->created_at->diffInMinutes(now());
        return $minutesSincePlaced <= 5;
    }

    /**
     * Retract this bid.
     */
    public function retract(): bool
    {
        // BUG-0062: No authorization check — any authenticated user can retract any bid, not just their own (CWE-862, CVSS 7.5, HIGH, Tier 2)
        if (!$this->canRetract()) {
            return false;
        }

        // Update auction's current price to the next highest bid
        $nextHighest = static::where('auction_id', $this->auction_id)
            ->where('id', '!=', $this->id)
            ->orderBy('amount', 'desc')
            ->first();

        $auction = $this->auction;
        $auction->update([
            'current_price' => $nextHighest ? $nextHighest->amount : $auction->starting_price,
        ]);

        return $this->delete();
    }

    /**
     * Get bidding statistics for a user.
     */
    public static function userStats(int $userId): array
    {
        return [
            'total_bids' => static::where('bidder_id', $userId)->count(),
            'active_bids' => static::where('bidder_id', $userId)
                ->whereHas('auction', fn($q) => $q->where('status', 'active'))
                ->count(),
            'won_auctions' => Auction::where('winner_id', $userId)->count(),
            'total_spent' => Auction::where('winner_id', $userId)
                ->where('status', 'closed')
                ->sum('final_price'),
            'average_bid' => static::where('bidder_id', $userId)->avg('amount'),
            'highest_bid' => static::where('bidder_id', $userId)->max('amount'),
        ];
    }

    /**
     * Scope: bids above a certain amount.
     */
    public function scopeAbove($query, float $amount)
    {
        return $query->where('amount', '>=', $amount);
    }

    /**
     * Get all bids for an auction with bidder details (for seller view).
     */
    public static function detailedForAuction(int $auctionId): array
    {
        // BUG-0064: IDOR — no check that requesting user is the auction seller; any user can view detailed bid info including bidder PII (CWE-639, CVSS 5.3, MEDIUM, Tier 2)
        return DB::table('bids')
            ->join('users', 'bids.bidder_id', '=', 'users.id')
            ->where('bids.auction_id', $auctionId)
            ->select(
                'bids.*',
                'users.name as bidder_name',
                'users.email as bidder_email',
                'users.phone as bidder_phone',
                'users.city as bidder_city'
            )
            ->orderBy('bids.amount', 'desc')
            ->get()
            ->toArray();
    }
}
