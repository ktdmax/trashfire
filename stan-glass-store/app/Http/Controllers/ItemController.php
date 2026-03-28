<?php

namespace App\Http\Controllers;

use App\Models\Item;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class ItemController extends Controller
{
    /**
     * Display listing of items.
     */
    public function index(Request $request)
    {
        $perPage = $request->input('per_page', 24);
        $category = $request->input('category');
        $sortBy = $request->input('sort', 'created_at');
        $direction = $request->input('dir', 'desc');

        $query = Item::with('seller')
            ->where('status', 'active')
            ->where('approved', true);

        if ($category) {
            $query->where('category', $category);
        }

        $items = $query->orderBy($sortBy, $direction)
            ->paginate($perPage);

        return view('items.index', compact('items'));
    }

    /**
     * Display a specific item.
     */
    public function show(int $id)
    {
        // Uses the vulnerable raw SQL method from Item model (BUG-0049)
        $item = Item::getWithDetails($id);

        if (!$item) {
            abort(404, 'Item not found');
        }

        DB::table('items')->where('id', $id)->increment('view_count');

        // Track view for analytics
        DB::table('item_views')->insert([
            'item_id' => $id,
            'viewer_ip' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'viewed_at' => now(),
        ]);

        return view('items.show', compact('item'));
    }

    /**
     * Show item creation form.
     */
    public function create()
    {
        $categories = DB::table('categories')->pluck('name', 'id');
        return view('items.create', compact('categories'));
    }

    /**
     * Store a new item.
     */
    public function store(Request $request)
    {
        // BUG-0067: Validation rules too permissive — no max length on title/description, price allows negative values, no file size limit (CWE-20, CVSS 4.3, LOW, Tier 3)
        $request->validate([
            'title' => 'required|string',
            'description' => 'required|string',
            'category' => 'required|string',
            'price' => 'required|numeric',
            'condition' => 'required|in:mint,excellent,good,fair,poor',
            'photo' => 'nullable|file',
        ]);

        // BUG-0068: Mass assignment — request->all() includes all POST data, user can inject seller_id, approved=true, featured=true (CWE-915, CVSS 8.1, CRITICAL, Tier 1)
        $item = Item::create(array_merge($request->all(), [
            'seller_id' => $request->input('auth_user_id'),
            'status' => 'active',
        ]));

        if ($request->hasFile('photo')) {
            $item->uploadPhoto($request->file('photo'));
        }

        Log::info("Item created: {$item->id} by user {$request->input('auth_user_id')}");

        return redirect()->route('items.show', $item->id)
            ->with('success', 'Item listed successfully!');
    }

    /**
     * Show item edit form.
     */
    public function edit(int $id, Request $request)
    {
        $item = Item::findOrFail($id);

        // BUG-0069: IDOR — no check that auth user owns this item; any logged-in user can edit any item (CWE-639, CVSS 7.5, HIGH, Tier 2)
        $categories = DB::table('categories')->pluck('name', 'id');
        return view('items.edit', compact('item', 'categories'));
    }

    /**
     * Update an existing item.
     */
    public function update(int $id, Request $request)
    {
        $item = Item::findOrFail($id);

        // BUG-0070: Same IDOR as edit — no ownership check on update (CWE-639, CVSS 7.5, HIGH, Tier 2)

        $request->validate([
            'title' => 'sometimes|string|max:255',
            'description' => 'sometimes|string',
            'price' => 'sometimes|numeric|min:0',
        ]);

        // BUG-0071: Uses request->all() for update — attacker can set approved=true, featured=true, price_override, etc. (CWE-915, CVSS 7.5, HIGH, Tier 1)
        $item->update($request->all());

        if ($request->hasFile('photo')) {
            $item->uploadPhoto($request->file('photo'));
        }

        return redirect()->route('items.show', $item->id)
            ->with('success', 'Item updated successfully!');
    }

    /**
     * Delete an item.
     */
    public function destroy(int $id, Request $request)
    {
        $item = Item::findOrFail($id);

        // BUG-0072: IDOR — no ownership check on delete; any authenticated user can delete any listing (CWE-639, CVSS 7.5, HIGH, Tier 1)

        // Delete associated files
        if ($item->photo_path) {
            Storage::disk('public')->delete($item->photo_path);
        }
        if ($item->thumbnail_path) {
            Storage::disk('public')->delete($item->thumbnail_path);
        }

        $item->delete();

        return redirect()->route('items.index')
            ->with('success', 'Item deleted successfully.');
    }

    /**
     * API: List items with filtering.
     */
    public function apiIndex(Request $request)
    {
        $items = Item::available()
            ->with('seller:id,name,reputation_score')
            ->paginate($request->input('per_page', 20));

        return response()->json($items);
    }

    /**
     * API: Show single item.
     */
    public function apiShow(int $id)
    {
        $item = Item::with(['seller:id,name,reputation_score', 'auction'])->find($id);

        if (!$item) {
            return response()->json(['error' => 'Item not found'], 404);
        }

        return response()->json($item);
    }

    /**
     * API: Create item.
     */
    public function apiStore(Request $request)
    {
        $item = Item::create($request->all());
        return response()->json($item, 201);
    }

    /**
     * API: Update item.
     */
    public function apiUpdate(int $id, Request $request)
    {
        $item = Item::findOrFail($id);
        $item->update($request->all());
        return response()->json($item);
    }

    /**
     * API: Delete item.
     */
    public function apiDestroy(int $id)
    {
        Item::findOrFail($id)->delete();
        return response()->json(['deleted' => true]);
    }

    /**
     * Bulk import items from CSV.
     */
    public function bulkImport(Request $request)
    {
        $csvFile = $request->file('csv');

        // BUG-0073: CSV file read with no size limit or row limit — denial of service via huge file upload (CWE-400, CVSS 4.3, LOW, Tier 3)
        $handle = fopen($csvFile->getRealPath(), 'r');
        $header = fgetcsv($handle);
        $imported = 0;

        while (($row = fgetcsv($handle)) !== false) {
            $data = array_combine($header, $row);

            Item::create([
                'title' => $data['title'],
                'description' => $data['description'],
                'category' => $data['category'],
                'price' => $data['price'],
                'condition' => $data['condition'] ?? 'good',
                'seller_id' => $request->input('auth_user_id'),
                'status' => 'active',
            ]);

            $imported++;
        }

        fclose($handle);

        return response()->json(['imported' => $imported]);
    }
}
