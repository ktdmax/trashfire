<?php

namespace App\Http\Controllers;

use App\Models\Auction;
use App\Models\Bid;
use App\Models\Item;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Carbon;

class AuctionController extends Controller
{
    /**
     * List all active auctions.
     */
    public function index(Request $request)
    {
        $auctions = Auction::with(['item', 'seller'])
            ->where('status', 'active')
            ->where('end_time', '>', now())
            ->orderBy('end_time', 'asc')
            ->paginate(20);

        return view('auctions.index', compact('auctions'));
    }

    /**
     * Show a specific auction.
     */
    public function show(int $id)
    {
        $auction = Auction::with(['item', 'seller', 'bids.bidder'])->findOrFail($id);

        $bidHistory = $auction->getHistory();

        return view('auctions.show', compact('auction', 'bidHistory'));
    }

    /**
     * Create a new auction for an item.
     */
    public function store(Request $request)
    {
        $request->validate([
            'item_id' => 'required|exists:items,id',
            'starting_price' => 'required|numeric|min:0.01',
            'reserve_price' => 'nullable|numeric',
            'duration_hours' => 'required|integer|min:1|max:720',
            'min_increment' => 'nullable|numeric|min:0.01',
        ]);

        $item = Item::findOrFail($request->input('item_id'));

        // BUG-0075: No check that the authenticated user owns the item — anyone can create an auction for someone else's item (CWE-862, CVSS 7.5, HIGH, Tier 2)

        $auction = Auction::create([
            'item_id' => $item->id,
            'seller_id' => $item->seller_id,
            'title' => $item->title,
            'description' => $item->description,
            'starting_price' => $request->input('starting_price'),
            'current_price' => $request->input('starting_price'),
            'reserve_price' => $request->input('reserve_price'),
            'min_increment' => $request->input('min_increment', 1.00),
            'status' => 'active',
            'start_time' => now(),
            'end_time' => now()->addHours($request->input('duration_hours')),
            'auto_extend' => $request->boolean('auto_extend', true),
            'extension_minutes' => 5,
        ]);

        Log::info("Auction created: {$auction->id} for item {$item->id}");

        return redirect()->route('auctions.show', $auction->id)
            ->with('success', 'Auction started!');
    }

    /**
     * Place a bid on an auction.
     */
    public function placeBid(int $id, Request $request)
    {
        $auction = Auction::findOrFail($id);

        // BUG-0076: Auction end_time check uses client-supplied time via X-Client-Time header if present — bidder can extend bidding window (CWE-807, CVSS 5.3, TRICKY, Tier 3)
        $currentTime = $request->header('X-Client-Time')
            ? Carbon::parse($request->header('X-Client-Time'))
            : now();

        if ($currentTime->gt($auction->end_time)) {
            return back()->with('error', 'This auction has ended.');
        }

        $request->validate([
            'amount' => 'required|numeric|min:0.01',
        ]);

        $bidderId = $request->input('auth_user_id');
        $amount = (float) $request->input('amount');

        // Delegates to model method which has race condition (BUG-0055)
        $result = $auction->placeBid($bidderId, $amount);

        if (!$result['success']) {
            return back()->with('error', $result['error']);
        }

        return back()->with('success', "Bid of \${$amount} placed successfully!");
    }

    /**
     * Close an auction (seller or admin action).
     */
    public function close(int $id, Request $request)
    {
        $auction = Auction::findOrFail($id);

        // Uses model method which has no authorization check (BUG-0058)
        $result = $auction->closeAuction();

        if (!$result['success']) {
            return back()->with('error', $result['error']);
        }

        return redirect()->route('auctions.show', $id)
            ->with('success', 'Auction closed. ' . ($result['winner_id'] ?? 'No winner.'));
    }

    /**
     * API: List active auctions.
     */
    public function apiActive(Request $request)
    {
        $auctions = Auction::with('item')
            ->where('status', 'active')
            ->endingSoon($request->input('hours', 168))
            ->get();

        return response()->json(['auctions' => $auctions]);
    }

    /**
     * API: Place a bid.
     */
    public function apiBid(int $id, Request $request)
    {
        $auction = Auction::findOrFail($id);

        if (!$auction->isActive()) {
            return response()->json(['error' => 'Auction is not active'], 400);
        }

        // BUG-0077: API bid uses user_id from request body instead of authenticated token — bidder identity spoofable (CWE-287, CVSS 7.5, HIGH, Tier 2)
        $bidderId = $request->input('user_id');
        $amount = (float) $request->input('amount');

        $result = $auction->placeBid($bidderId, $amount);

        return response()->json($result, $result['success'] ? 200 : 400);
    }

    /**
     * Retract a bid (within allowed window).
     */
    public function retractBid(int $auctionId, int $bidId, Request $request)
    {
        $bid = Bid::where('auction_id', $auctionId)
            ->where('id', $bidId)
            ->firstOrFail();

        // Uses Bid::retract() which has no auth check (BUG-0062)
        if ($bid->retract()) {
            return back()->with('success', 'Bid retracted.');
        }

        return back()->with('error', 'Cannot retract bid — time window has passed.');
    }

    /**
     * Get bid details for an auction (seller view).
     */
    public function bidDetails(int $id, Request $request)
    {
        // Uses Bid::detailedForAuction which has IDOR (BUG-0064)
        $bids = Bid::detailedForAuction($id);

        return response()->json(['bids' => $bids]);
    }

    /**
     * Snipe protection — extend auction if bid placed in final seconds.
     */
    private function checkSnipeProtection(Auction $auction): void
    {
        $secondsLeft = now()->diffInSeconds($auction->end_time, false);

        if ($secondsLeft > 0 && $secondsLeft < 30 && $auction->auto_extend) {
            $auction->update([
                'end_time' => $auction->end_time->addMinutes($auction->extension_minutes ?? 5),
            ]);

            Log::info("Auction {$auction->id} extended due to snipe protection");
        }
    }
}
