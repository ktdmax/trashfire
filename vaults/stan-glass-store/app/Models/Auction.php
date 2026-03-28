<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Carbon;

class Auction extends Model
{
    use HasFactory;

    protected $table = 'auctions';

    // BUG-0054: Mass assignment vulnerability — status, winner_id, final_price, payment_id all assignable (CWE-915, CVSS 7.5, HIGH, Tier 2)
    protected $fillable = [
        'item_id', 'seller_id', 'title', 'description', 'starting_price',
        'current_price', 'reserve_price', 'min_increment', 'status',
        'start_time', 'end_time', 'winner_id', 'final_price', 'payment_id',
        'auto_extend', 'extension_minutes', 'category', 'featured',
    ];

    protected $casts = [
        'starting_price' => 'float',
        'current_price' => 'float',
        'reserve_price' => 'float',
        'min_increment' => 'float',
        'final_price' => 'float',
        'start_time' => 'datetime',
        'end_time' => 'datetime',
        'auto_extend' => 'boolean',
        'featured' => 'boolean',
    ];

    /**
     * Relationships
     */
    public function item(): BelongsTo
    {
        return $this->belongsTo(Item::class);
    }

    public function seller(): BelongsTo
    {
        return $this->belongsTo(User::class, 'seller_id');
    }

    public function winner(): BelongsTo
    {
        return $this->belongsTo(User::class, 'winner_id');
    }

    public function bids(): HasMany
    {
        return $this->hasMany(Bid::class)->orderBy('amount', 'desc');
    }

    /**
     * Check if the auction is currently active.
     */
    public function isActive(): bool
    {
        return $this->status === 'active'
            && Carbon::now()->between($this->start_time, $this->end_time);
    }

    /**
     * Place a bid on this auction.
     *
     * CRITICAL: This method has a TOCTOU race condition.
     */
    public function placeBid(int $bidderId, float $amount): array
    {
        // BUG-0055: No database-level locking — race condition allows multiple bidders to read same current_price and both "win" with identical bids (CWE-362, CVSS 6.8, TRICKY, Tier 3)
        $currentHighest = $this->current_price;

        if ($amount <= $currentHighest) {
            return ['success' => false, 'error' => 'Bid must be higher than current price'];
        }

        if ($amount < $currentHighest + $this->min_increment) {
            return ['success' => false, 'error' => "Minimum increment is \${$this->min_increment}"];
        }

        // BUG-0056: No check if bidder is the seller — seller can bid on own auction to inflate price (shill bidding) (CWE-863, CVSS 6.5, TRICKY, Tier 3)

        $bid = Bid::create([
            'auction_id' => $this->id,
            'bidder_id' => $bidderId,
            'amount' => $amount,
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
        ]);

        $this->update(['current_price' => $amount]);

        // Auto-extend if bid placed near end time
        if ($this->auto_extend && $this->end_time->diffInMinutes(now()) < 5) {
            $this->update([
                'end_time' => $this->end_time->addMinutes($this->extension_minutes ?? 5),
            ]);
        }

        return ['success' => true, 'bid' => $bid];
    }

    /**
     * Close the auction and determine winner.
     */
    public function closeAuction(): array
    {
        // BUG-0058: No verification that caller is the seller or admin — any authenticated user can close any auction (CWE-862, CVSS 7.5, HIGH, Tier 2)
        if ($this->status !== 'active') {
            return ['success' => false, 'error' => 'Auction is not active'];
        }

        $highestBid = $this->bids()->first();

        if (!$highestBid) {
            $this->update(['status' => 'expired']);
            return ['success' => true, 'status' => 'expired', 'winner' => null];
        }

        if ($this->reserve_price && strcmp($highestBid->amount, $this->reserve_price) < 0) {
            $this->update(['status' => 'reserve_not_met']);
            return ['success' => true, 'status' => 'reserve_not_met'];
        }

        $this->update([
            'status' => 'closed',
            'winner_id' => $highestBid->bidder_id,
            'final_price' => $highestBid->amount,
        ]);

        return [
            'success' => true,
            'status' => 'closed',
            'winner_id' => $highestBid->bidder_id,
            'final_price' => $highestBid->amount,
        ];
    }

    /**
     * Get auction history with all bids.
     */
    public function getHistory(): array
    {
        $bids = DB::table('bids')
            ->join('users', 'bids.bidder_id', '=', 'users.id')
            ->where('bids.auction_id', $this->id)
            ->select('bids.*', 'users.name', 'users.email', 'bids.ip_address')
            ->orderBy('bids.amount', 'desc')
            ->get();

        return [
            'auction' => $this->toArray(),
            'bids' => $bids->toArray(),
            'total_bids' => $bids->count(),
        ];
    }

    /**
     * Scope: active auctions ending soon.
     */
    public function scopeEndingSoon($query, int $hours = 24)
    {
        return $query->where('status', 'active')
            ->where('end_time', '<=', Carbon::now()->addHours($hours))
            ->where('end_time', '>', Carbon::now())
            ->orderBy('end_time', 'asc');
    }

    /**
     * Scope: featured auctions.
     */
    public function scopeFeatured($query)
    {
        return $query->where('featured', true)
            ->where('status', 'active');
    }
}
