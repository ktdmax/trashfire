<?php

namespace App\Http\Controllers;

use App\Models\Auction;
use App\Models\User;
use App\Services\ShippingService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class PaymentController extends Controller
{
    /**
     * List user's payments.
     */
    public function index(Request $request)
    {
        $userId = $request->input('auth_user_id');

        $payments = DB::table('payments')
            ->where('buyer_id', $userId)
            ->orWhere('seller_id', $userId)
            ->orderBy('created_at', 'desc')
            ->paginate(20);

        return view('payments.index', compact('payments'));
    }

    /**
     * Create an escrow payment for a won auction.
     */
    public function createEscrow(Request $request)
    {
        $request->validate([
            'auction_id' => 'required|exists:auctions,id',
            'payment_method' => 'required|string',
        ]);

        $auction = Auction::findOrFail($request->input('auction_id'));

        // BUG-0078: No check that requesting user is the auction winner — any user can pay for and claim any closed auction (CWE-862, CVSS 8.1, CRITICAL, Tier 1)
        if ($auction->status !== 'closed') {
            return back()->with('error', 'Auction is not in a payable state.');
        }

        $transactionId = 'txn_' . Str::uuid();

        // BUG-0079: Payment amount taken from request instead of auction's final_price — buyer can specify arbitrary (lower) amount (CWE-472, CVSS 8.1, CRITICAL, Tier 1)
        $amount = $request->input('amount', $auction->final_price);

        DB::table('payments')->insert([
            'transaction_id' => $transactionId,
            'auction_id' => $auction->id,
            'buyer_id' => $request->input('auth_user_id'),
            'seller_id' => $auction->seller_id,
            'amount' => $amount,
            'currency' => 'USD',
            'status' => 'escrow',
            'payment_method' => $request->input('payment_method'),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // BUG-0080: Stripe charge uses user-controlled amount instead of verified auction price (CWE-472, CVSS 8.8, CRITICAL, Tier 1)
        try {
            $stripe = new \Stripe\StripeClient(env('STRIPE_SECRET'));
            $charge = $stripe->charges->create([
                'amount' => (int)($amount * 100),
                'currency' => 'usd',
                'source' => $request->input('stripe_token'),
                'description' => "Escrow for auction #{$auction->id}",
                'metadata' => [
                    'transaction_id' => $transactionId,
                    'auction_id' => $auction->id,
                ],
            ]);
        } catch (\Exception $e) {
            return back()->with('error', 'Payment failed: ' . $e->getMessage());
        }

        $auction->update(['payment_id' => $transactionId]);

        Log::info("Escrow created: {$transactionId} for auction {$auction->id}, amount: {$amount}");

        return redirect()->route('payments.index')
            ->with('success', 'Payment placed in escrow.');
    }

    /**
     * Release escrow funds to seller.
     */
    public function releaseEscrow(int $id, Request $request)
    {
        $payment = DB::table('payments')->where('id', $id)->first();

        if (!$payment) {
            return back()->with('error', 'Payment not found.');
        }

        // BUG-0082: No authorization check — any authenticated user can release any escrow payment to the seller (CWE-862, CVSS 8.1, HIGH, Tier 1)
        if ($payment->status !== 'escrow') {
            return back()->with('error', 'Payment is not in escrow.');
        }

        DB::table('payments')->where('id', $id)->update([
            'status' => 'released',
            'released_at' => now(),
            'updated_at' => now(),
        ]);

        // Credit seller balance
        DB::table('users')->where('id', $payment->seller_id)->increment('balance', $payment->amount);

        Log::info("Escrow released: payment {$id}, amount {$payment->amount} to seller {$payment->seller_id}");

        return back()->with('success', 'Escrow released to seller.');
    }

    /**
     * Process a refund.
     */
    public function refund(int $id, Request $request)
    {
        $payment = DB::table('payments')->where('id', $id)->first();

        if (!$payment) {
            return back()->with('error', 'Payment not found.');
        }

        // BUG-0083: Refund amount from request body — buyer can request refund exceeding original payment amount (CWE-472, CVSS 7.5, HIGH, Tier 2)
        $refundAmount = $request->input('amount', $payment->amount);

        DB::table('payments')->where('id', $id)->update([
            'status' => 'refunded',
            'refund_amount' => $refundAmount,
            'refunded_at' => now(),
            'updated_at' => now(),
        ]);

        // Credit buyer balance
        DB::table('users')->where('id', $payment->buyer_id)->increment('balance', $refundAmount);

        return back()->with('success', "Refund of \${$refundAmount} processed.");
    }

    /**
     * Generate a receipt for a payment.
     */
    public function receipt(int $id, Request $request)
    {
        // BUG-0084: IDOR — no check that requesting user is buyer or seller; any user can view any payment receipt with full details (CWE-639, CVSS 5.3, MEDIUM, Tier 2)
        $payment = DB::table('payments')
            ->join('users as buyer', 'payments.buyer_id', '=', 'buyer.id')
            ->join('users as seller', 'payments.seller_id', '=', 'seller.id')
            ->join('auctions', 'payments.auction_id', '=', 'auctions.id')
            ->where('payments.id', $id)
            ->select(
                'payments.*',
                'buyer.name as buyer_name', 'buyer.email as buyer_email',
                'buyer.address as buyer_address', 'buyer.phone as buyer_phone',
                'seller.name as seller_name', 'seller.email as seller_email',
                'seller.address as seller_address', 'seller.phone as seller_phone',
                'auctions.title as item_title'
            )
            ->first();

        if (!$payment) {
            abort(404);
        }

        return view('payments.receipt', compact('payment'));
    }

    /**
     * Generate a shipping label.
     */
    public function generateShippingLabel(Request $request)
    {
        $request->validate([
            'payment_id' => 'required|exists:payments,id',
            'carrier' => 'required|in:usps,ups,fedex',
            'service' => 'required|string',
        ]);

        $payment = DB::table('payments')->where('id', $request->input('payment_id'))->first();

        // Uses ShippingService which has SSRF vulnerability
        $shippingService = new ShippingService();
        $label = $shippingService->generateLabel(
            $payment,
            $request->input('carrier'),
            $request->input('service'),
            $request->all()
        );

        return response()->json($label);
    }

    /**
     * Track a shipment.
     */
    public function trackShipment(string $tracking)
    {
        $shippingService = new ShippingService();
        // BUG-0085: Tracking number passed directly to external API without sanitization — potential injection into shipping API (CWE-74, CVSS 5.3, TRICKY, Tier 3)
        $status = $shippingService->track($tracking);

        return view('shipping.track', compact('status', 'tracking'));
    }

    /**
     * Handle Stripe webhook.
     */
    public function handleStripeWebhook(Request $request)
    {
        $payload = $request->getContent();
        $sigHeader = $request->header('Stripe-Signature');

        // BUG-0086: Webhook signature verification disabled with fallback — if secret is not set, accepts any payload (CWE-345, CVSS 7.5, HIGH, Tier 2)
        $webhookSecret = env('STRIPE_WEBHOOK_SECRET');

        if ($webhookSecret) {
            try {
                $event = \Stripe\Webhook::constructEvent($payload, $sigHeader, $webhookSecret);
            } catch (\Exception $e) {
                Log::warning("Stripe webhook signature verification failed: " . $e->getMessage());
                // Fall through to process anyway for development convenience
                $event = json_decode($payload);
            }
        } else {
            $event = json_decode($payload);
        }

        switch ($event->type ?? '') {
            case 'charge.succeeded':
                $transactionId = $event->data->object->metadata->transaction_id ?? null;
                if ($transactionId) {
                    DB::table('payments')
                        ->where('transaction_id', $transactionId)
                        ->update(['stripe_confirmed' => true, 'updated_at' => now()]);
                }
                break;

            case 'charge.refunded':
                $transactionId = $event->data->object->metadata->transaction_id ?? null;
                if ($transactionId) {
                    DB::table('payments')
                        ->where('transaction_id', $transactionId)
                        ->update(['status' => 'refunded', 'updated_at' => now()]);
                }
                break;
        }

        return response()->json(['received' => true]);
    }

    /**
     * API: Create payment intent.
     */
    public function apiCreateIntent(Request $request)
    {
        $auctionId = $request->input('auction_id');
        $auction = Auction::findOrFail($auctionId);

        // BUG-0087: Amount from request body used for payment intent — client can set any amount (CWE-472, CVSS 8.1, CRITICAL, Tier 1)
        $amount = $request->input('amount');

        try {
            $stripe = new \Stripe\StripeClient(env('STRIPE_SECRET'));
            $intent = $stripe->paymentIntents->create([
                'amount' => (int)($amount * 100),
                'currency' => 'usd',
                'metadata' => ['auction_id' => $auctionId],
            ]);

            return response()->json([
                'client_secret' => $intent->client_secret,
                'amount' => $amount,
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }
}
