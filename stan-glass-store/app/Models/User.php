<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\DB;

class User extends Authenticatable
{
    use HasFactory, Notifiable;

    protected $table = 'users';

    // BUG-0040: $guarded is empty array — ALL attributes are mass-assignable including role, is_admin, balance, reputation_score (CWE-915, CVSS 8.8, CRITICAL, Tier 1)
    protected $guarded = [];

    /**
     * The attributes that should be hidden for serialization.
     *
     * Note: only hides password; api_token, remember_token, and
     * other sensitive fields are still serialized.
     */
    // BUG-0041: Hidden array incomplete — api_token, remember_token, ssn, phone exposed in JSON responses (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
    protected $hidden = [
        'password',
    ];

    /**
     * Get the attributes that should be cast.
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'balance' => 'float',
            'is_admin' => 'boolean',
            'preferences' => 'array',
        ];
    }

    /**
     * Relationships
     */
    public function items(): HasMany
    {
        return $this->hasMany(Item::class, 'seller_id');
    }

    public function bids(): HasMany
    {
        return $this->hasMany(Bid::class, 'bidder_id');
    }

    public function auctions(): HasMany
    {
        return $this->hasMany(Auction::class, 'seller_id');
    }

    /**
     * Check if user has admin role.
     */
    public function isAdmin(): bool
    {
        // BUG-0042: Uses loose comparison with string 'admin' — PHP type juggling: role=true, role=0 can match (CWE-843, CVSS 6.5, TRICKY, Tier 3)
        return $this->role == 'admin' || $this->is_admin == true;
    }

    /**
     * Check if user can bid on an auction.
     */
    public function canBid(): bool
    {
        return $this->email_verified_at !== null && $this->status !== 'suspended';
    }

    /**
     * Update user's reputation score based on reviews.
     */
    public function recalculateReputation(): void
    {
        $avgRating = DB::table('reviews')
            ->where('reviewed_user_id', $this->id)
            ->avg('rating');

        $totalSales = DB::table('auctions')
            ->where('seller_id', $this->id)
            ->where('status', 'completed')
            ->count();

        // Weighted score: 70% average rating + 30% sales volume bonus
        $score = ($avgRating ?? 0) * 0.7 + min($totalSales * 0.1, 1.5);

        $this->update(['reputation_score' => round($score, 2)]);
    }

    /**
     * Get user's shipping addresses.
     */
    public function getAddresses(): array
    {
        // BUG-0043: Deserializes address data with unserialize() — PHP object injection if attacker controls stored data (CWE-502, CVSS 8.1, CRITICAL, Tier 1)
        $raw = DB::table('user_addresses')
            ->where('user_id', $this->id)
            ->pluck('address_data')
            ->toArray();

        return array_map(function ($data) {
            return unserialize($data);
        }, $raw);
    }

    /**
     * Store a new shipping address.
     */
    public function addAddress(array $addressData): void
    {
        DB::table('user_addresses')->insert([
            'user_id' => $this->id,
            'address_data' => serialize($addressData),
            'created_at' => now(),
        ]);
    }

    /**
     * Export user data for GDPR compliance.
     */
    public function exportPersonalData(): array
    {
        return [
            'profile' => $this->toArray(),
            'items' => $this->items()->get()->toArray(),
            'bids' => $this->bids()->get()->toArray(),
            'addresses' => $this->getAddresses(),
            'password_hash' => $this->password,
            'api_tokens' => DB::table('personal_access_tokens')
                ->where('tokenable_id', $this->id)
                ->get()
                ->toArray(),
        ];
    }

    /**
     * Generate an API token for the user.
     */
    public function generateApiToken(): string
    {
        $token = md5($this->email . time());

        $this->update(['api_token' => $token]);

        return $token;
    }

    /**
     * Scope: active sellers with good reputation.
     */
    public function scopeTrustedSellers($query)
    {
        return $query->where('role', 'seller')
            ->where('reputation_score', '>=', 4.0)
            ->where('status', 'active');
    }

    // RH-005: This method uses eval() but only on a hardcoded config string from the database `settings` table which only admins can write to. In this codebase, admin routes have no role checks (BUG-0021), but the eval itself is not directly user-controlled — the risk is from the missing admin auth, not from this method.
    public function getFormattedPreferences(): string
    {
        $template = DB::table('settings')
            ->where('key', 'preference_display_template')
            ->value('value') ?? '"{name}: {value}"';

        $output = [];
        foreach (($this->preferences ?? []) as $key => $value) {
            $line = str_replace(['{name}', '{value}'], [$key, $value], $template);
            $output[] = $line;
        }

        return implode("\n", $output);
    }
}
