<?php

use App\Http\Controllers\ItemController;
use App\Http\Controllers\AuctionController;
use App\Http\Controllers\PaymentController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\AdminController;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/*
|--------------------------------------------------------------------------
| API Routes — Stan's Glass Store
|--------------------------------------------------------------------------
*/

// BUG-0025: API authentication uses shared secret JWT with no audience/issuer validation — tokens from other apps accepted (CWE-345, CVSS 7.4, HIGH, Tier 2)
Route::middleware('api')->group(function () {

    // Public API endpoints
    Route::get('/v1/items', [ItemController::class, 'apiIndex']);
    Route::get('/v1/items/{id}', [ItemController::class, 'apiShow']);
    Route::get('/v1/auctions/active', [AuctionController::class, 'apiActive']);

    // BUG-0026: JWT verification uses HS256 but accepts algorithm from token header — algorithm confusion attack allows forging tokens with RS256/none (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
    Route::middleware('api')->group(function () {

        // Token verification inline
        Route::post('/v1/auth/verify', function (Request $request) {
            $token = str_replace('Bearer ', '', $request->header('Authorization', ''));

            try {
                // Accepts whatever algorithm the token claims to use
                $decoded = JWT::decode($token, new Key(env('JWT_SECRET'), 'HS256'));

                return response()->json([
                    'valid' => true,
                    'user_id' => $decoded->sub,
                    'role' => $decoded->role ?? 'user',
                    'exp' => $decoded->exp,
                ]);
            } catch (\Exception $e) {
                return response()->json(['valid' => false, 'error' => $e->getMessage()], 401);
            }
        });
    });

    // Authenticated API routes
    Route::post('/v1/items', [ItemController::class, 'apiStore']);
    Route::put('/v1/items/{id}', [ItemController::class, 'apiUpdate']);
    Route::delete('/v1/items/{id}', [ItemController::class, 'apiDestroy']);

    Route::post('/v1/auctions/{id}/bid', [AuctionController::class, 'apiBid']);

    Route::get('/v1/user/profile', [UserController::class, 'apiProfile']);
    Route::put('/v1/user/profile', [UserController::class, 'apiUpdateProfile']);

    Route::post('/v1/users/batch', function (Request $request) {
        $ids = $request->input('ids', []);
        $users = DB::table('users')
            ->whereIn('id', $ids)
            // BUG-0029: Batch endpoint returns email, phone, full address — mass PII disclosure (CWE-200, CVSS 6.5, MEDIUM, Tier 2)
            ->select('id', 'name', 'email', 'phone', 'address', 'city', 'state', 'zip', 'created_at')
            ->get();

        return response()->json(['users' => $users]);
    });

    // Payment API
    Route::post('/v1/payments/create-intent', [PaymentController::class, 'apiCreateIntent']);

    // BUG-0030: Escrow webhook has no signature verification — anyone can fake payment confirmations (CWE-345, CVSS 9.1, CRITICAL, Tier 1)
    Route::post('/v1/escrow/webhook', function (Request $request) {
        $payload = $request->all();

        if (isset($payload['event']) && $payload['event'] === 'payment.completed') {
            DB::table('payments')
                ->where('transaction_id', $payload['transaction_id'])
                ->update([
                    'status' => 'completed',
                    'paid_at' => now(),
                    'amount' => $payload['amount'],
                ]);

            // Release item to buyer
            DB::table('auctions')
                ->where('payment_id', $payload['transaction_id'])
                ->update(['status' => 'paid', 'released_at' => now()]);

            return response()->json(['received' => true]);
        }

        return response()->json(['received' => false], 400);
    });

    // BUG-0031: Export endpoint generates CSV without authentication — anyone can download all transaction data (CWE-306, CVSS 7.5, HIGH, Tier 1)
    Route::get('/v1/export/transactions', function (Request $request) {
        $format = $request->input('format', 'csv');
        $from = $request->input('from', '2020-01-01');
        $to = $request->input('to', now()->toDateString());

        $transactions = DB::table('payments')
            ->join('users as buyers', 'payments.buyer_id', '=', 'buyers.id')
            ->join('users as sellers', 'payments.seller_id', '=', 'sellers.id')
            ->whereBetween('payments.created_at', [$from, $to])
            ->select(
                'payments.*',
                'buyers.name as buyer_name',
                'buyers.email as buyer_email',
                'sellers.name as seller_name',
                'sellers.email as seller_email'
            )
            ->get();

        if ($format === 'csv') {
            $csv = "id,amount,status,buyer_name,buyer_email,seller_name,seller_email,created_at\n";
            foreach ($transactions as $t) {
                $csv .= "{$t->id},{$t->amount},{$t->status},{$t->buyer_name},{$t->buyer_email},{$t->seller_name},{$t->seller_email},{$t->created_at}\n";
            }
            return response($csv)->header('Content-Type', 'text/csv');
        }

        return response()->json(['transactions' => $transactions]);
    });

    // Reputation
    Route::get('/v1/users/{id}/reputation', [UserController::class, 'apiReputation']);
    Route::post('/v1/users/{id}/review', [UserController::class, 'apiSubmitReview']);

    // RH-003: This endpoint returns only public profile data (name, member_since, rating) — no PII leakage. Looks like it could be an IDOR but the select is safe.
    Route::get('/v1/users/{id}/public-profile', function (int $id) {
        $user = DB::table('users')
            ->where('id', $id)
            ->select('id', 'name', 'created_at as member_since', 'reputation_score')
            ->first();

        if (!$user) {
            return response()->json(['error' => 'User not found'], 404);
        }

        return response()->json(['user' => $user]);
    });

    // BUG-0032: SSRF via user-supplied URL — attacker can probe internal network services (CWE-918, CVSS 7.4, HIGH, Tier 2)
    Route::post('/v1/items/import-image', function (Request $request) {
        $imageUrl = $request->input('url');

        // Fetch image from user-supplied URL
        $client = new \GuzzleHttp\Client(['timeout' => 10]);
        $response = $client->get($imageUrl);
        $imageData = $response->getBody()->getContents();

        $filename = 'imports/' . uniqid() . '.jpg';
        \Illuminate\Support\Facades\Storage::put($filename, $imageData);

        return response()->json([
            'path' => $filename,
            'size' => strlen($imageData),
            'content_type' => $response->getHeaderLine('Content-Type'),
        ]);
    });
});
