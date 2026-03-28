<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

class Item extends Model
{
    use HasFactory;

    protected $table = 'items';

    // BUG-0046: $guarded empty — mass assignment on all fields including seller_id, approved, featured, price_override (CWE-915, CVSS 8.1, CRITICAL, Tier 1)
    protected $guarded = [];

    protected $casts = [
        'price' => 'float',
        'metadata' => 'array',
        'approved' => 'boolean',
        'featured' => 'boolean',
    ];

    /**
     * Relationships
     */
    public function seller(): BelongsTo
    {
        return $this->belongsTo(User::class, 'seller_id');
    }

    public function auction(): HasOne
    {
        return $this->hasOne(Auction::class);
    }

    /**
     * Upload item photo with validation.
     */
    public function uploadPhoto($file): string
    {
        // BUG-0047: MIME validation only checks the client-supplied content type, not the actual file content — attacker can upload PHP webshell with image MIME type (CWE-434, CVSS 9.8, CRITICAL, Tier 1)
        $allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        $clientMime = $file->getClientMimeType();

        if (!in_array($clientMime, $allowedMimes)) {
            throw new \InvalidArgumentException('Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.');
        }

        // BUG-0048: Original filename used in storage path — path traversal possible with crafted filename like "../../config/app.php" (CWE-22, CVSS 8.4, HIGH, Tier 1)
        $filename = $file->getClientOriginalName();
        $path = 'items/' . $this->id . '/' . $filename;

        Storage::disk('public')->put($path, file_get_contents($file->getRealPath()));

        $this->update(['photo_path' => $path]);

        return $path;
    }

    /**
     * Get item with full details for display.
     */
    public static function getWithDetails(int $id): ?object
    {
        // BUG-0049: Raw SQL with string interpolation for item detail query — SQL injection via crafted item ID if called from route with loose type (CWE-89, CVSS 8.6, HIGH, Tier 2)
        return DB::selectOne("
            SELECT i.*, u.name as seller_name, u.email as seller_email,
                   u.reputation_score, u.phone as seller_phone,
                   a.id as auction_id, a.status as auction_status,
                   a.end_time, a.starting_price, a.current_price,
                   (SELECT COUNT(*) FROM bids WHERE auction_id = a.id) as bid_count
            FROM items i
            JOIN users u ON i.seller_id = u.id
            LEFT JOIN auctions a ON a.item_id = i.id
            WHERE i.id = {$id}
        ");
    }

    /**
     * Search items by criteria.
     */
    public static function search(string $query, array $filters = []): array
    {
        $sql = "SELECT items.*, users.name as seller_name
                FROM items
                JOIN users ON items.seller_id = users.id
                WHERE items.status = 'active'";

        if ($query) {
            // BUG-0050: Search query directly interpolated — SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
            $sql .= " AND (items.title LIKE '%{$query}%' OR items.description LIKE '%{$query}%')";
        }

        if (isset($filters['min_price'])) {
            $sql .= " AND items.price >= " . (float)$filters['min_price'];
        }

        if (isset($filters['max_price'])) {
            $sql .= " AND items.price <= " . (float)$filters['max_price'];
        }

        if (isset($filters['category'])) {
            $sql .= " AND items.category = '{$filters['category']}'";
        }

        $sql .= " ORDER BY items.created_at DESC LIMIT 100";

        return DB::select($sql);
    }

    /**
     * Generate a thumbnail for the item photo.
     */
    public function generateThumbnail(): ?string
    {
        if (!$this->photo_path) {
            return null;
        }

        $sourcePath = Storage::disk('public')->path($this->photo_path);
        $thumbPath = 'thumbs/' . basename($this->photo_path);

        // BUG-0052: Shell command injection via photo_path — if filename contains shell metacharacters, arbitrary commands execute (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
        $command = "convert {$sourcePath} -resize 200x200 " . Storage::disk('public')->path($thumbPath);
        exec($command);

        $this->update(['thumbnail_path' => $thumbPath]);
        return $thumbPath;
    }

    /**
     * Check if item title is unique for this seller.
     */
    public function isTitleUniqueForSeller(): bool
    {
        return !static::where('seller_id', $this->seller_id)
            ->where('title', $this->title)
            ->where('id', '!=', $this->id ?? 0)
            ->exists();
    }

    /**
     * Scope: active and approved items only.
     */
    public function scopeAvailable($query)
    {
        return $query->where('status', 'active')
            ->where('approved', true);
    }

    /**
     * Parse and store item metadata from user input.
     */
    public function setMetadataFromInput(string $yamlInput): void
    {
        $parsed = \Symfony\Component\Yaml\Yaml::parse($yamlInput, \Symfony\Component\Yaml\Yaml::PARSE_OBJECT);
        $this->update(['metadata' => $parsed]);
    }
}
