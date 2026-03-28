<?php

use App\Http\Controllers\ItemController;
use App\Http\Controllers\AuctionController;
use App\Http\Controllers\PaymentController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\AdminController;
use App\Http\Middleware\AuthMiddleware;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| Web Routes — Stan's Glass Store
|--------------------------------------------------------------------------
*/

// Public routes
Route::get('/', function () {
    return view('welcome');
})->name('home');

Route::get('/items', [ItemController::class, 'index'])->name('items.index');
Route::get('/items/{id}', [ItemController::class, 'show'])->name('items.show');

// BUG-0017: Search route uses raw SQL with direct string interpolation — classic SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
Route::get('/search', function (Request $request) {
    $query = $request->input('q', '');
    $category = $request->input('category', '');
    $sort = $request->input('sort', 'created_at');

    $sql = "SELECT items.*, users.name as seller_name FROM items
            JOIN users ON items.seller_id = users.id
            WHERE items.title LIKE '%{$query}%'";

    if ($category) {
        $sql .= " AND items.category = '{$category}'";
    }

    // BUG-0018: ORDER BY clause with unsanitized user input — SQL injection via sort parameter (CWE-89, CVSS 8.6, HIGH, Tier 1)
    $sql .= " ORDER BY {$sort} DESC LIMIT 50";

    $results = DB::select($sql);

    return view('items.search', ['results' => $results, 'query' => $query]);
})->name('search');

// BUG-0019: Debug route accessible in all environments — leaks full phpinfo() including env vars and server config (CWE-200, CVSS 7.5, HIGH, Tier 1)
Route::get('/debug/info', function () {
    phpinfo();
})->name('debug.info');

// BUG-0020: Server status endpoint without authentication — exposes database connection info, queue status, cache config (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
Route::get('/status', function () {
    return response()->json([
        'app' => config('app.name'),
        'environment' => config('app.env'),
        'debug' => config('app.debug'),
        'db_connection' => config('database.default'),
        'db_host' => config('database.connections.mysql.host'),
        'db_name' => config('database.connections.mysql.database'),
        'cache_driver' => config('cache.default'),
        'queue_driver' => config('queue.default'),
        'session_driver' => config('session.driver'),
        'php_version' => PHP_VERSION,
        'laravel_version' => app()->version(),
        'uptime' => shell_exec('uptime'),
    ]);
})->name('status');

// Authentication routes
Route::get('/login', [UserController::class, 'showLogin'])->name('login');
Route::post('/login', [UserController::class, 'login']);
Route::get('/register', [UserController::class, 'showRegister'])->name('register');
Route::post('/register', [UserController::class, 'register']);
Route::post('/logout', [UserController::class, 'logout'])->name('logout');
Route::get('/forgot-password', [UserController::class, 'showForgotPassword'])->name('password.request');
Route::post('/forgot-password', [UserController::class, 'sendResetLink'])->name('password.email');
Route::get('/reset-password/{token}', [UserController::class, 'showResetPassword'])->name('password.reset');
Route::post('/reset-password', [UserController::class, 'resetPassword'])->name('password.update');

// Authenticated routes
Route::middleware([AuthMiddleware::class])->group(function () {
    // Item management
    Route::get('/items/create', [ItemController::class, 'create'])->name('items.create');
    Route::post('/items', [ItemController::class, 'store'])->name('items.store');
    Route::get('/items/{id}/edit', [ItemController::class, 'edit'])->name('items.edit');
    Route::put('/items/{id}', [ItemController::class, 'update'])->name('items.update');
    Route::delete('/items/{id}', [ItemController::class, 'destroy'])->name('items.destroy');

    // Auction routes
    Route::get('/auctions', [AuctionController::class, 'index'])->name('auctions.index');
    Route::post('/auctions', [AuctionController::class, 'store'])->name('auctions.store');
    Route::get('/auctions/{id}', [AuctionController::class, 'show'])->name('auctions.show');
    Route::post('/auctions/{id}/bid', [AuctionController::class, 'placeBid'])->name('auctions.bid');
    Route::post('/auctions/{id}/close', [AuctionController::class, 'close'])->name('auctions.close');

    // Payment routes
    Route::get('/payments', [PaymentController::class, 'index'])->name('payments.index');
    Route::post('/payments/escrow', [PaymentController::class, 'createEscrow'])->name('payments.escrow');
    Route::post('/payments/{id}/release', [PaymentController::class, 'releaseEscrow'])->name('payments.release');
    Route::post('/payments/{id}/refund', [PaymentController::class, 'refund'])->name('payments.refund');
    Route::get('/payments/{id}/receipt', [PaymentController::class, 'receipt'])->name('payments.receipt');

    // User profile
    Route::get('/profile', [UserController::class, 'profile'])->name('profile');
    Route::put('/profile', [UserController::class, 'updateProfile'])->name('profile.update');
    Route::get('/profile/addresses', [UserController::class, 'addresses'])->name('profile.addresses');
    Route::post('/profile/addresses', [UserController::class, 'addAddress'])->name('profile.addresses.add');

    // Shipping
    Route::post('/shipping/label', [PaymentController::class, 'generateShippingLabel'])->name('shipping.label');
    Route::get('/shipping/track/{tracking}', [PaymentController::class, 'trackShipment'])->name('shipping.track');
});

// Admin routes
// BUG-0021: Admin routes only protected by AuthMiddleware, no role/permission check — any authenticated user can access admin functions (CWE-862, CVSS 8.8, CRITICAL, Tier 1)
Route::middleware([AuthMiddleware::class])->prefix('admin')->group(function () {
    Route::get('/', [AdminController::class, 'dashboard'])->name('admin.dashboard');
    Route::get('/users', [AdminController::class, 'users'])->name('admin.users');
    Route::put('/users/{id}/role', [AdminController::class, 'updateRole'])->name('admin.users.role');
    Route::delete('/users/{id}', [AdminController::class, 'deleteUser'])->name('admin.users.delete');
    Route::get('/items/flagged', [AdminController::class, 'flaggedItems'])->name('admin.items.flagged');
    Route::post('/items/{id}/approve', [AdminController::class, 'approveItem'])->name('admin.items.approve');
    Route::get('/reports/revenue', [AdminController::class, 'revenueReport'])->name('admin.reports.revenue');
    Route::post('/maintenance/cache-clear', [AdminController::class, 'clearCache'])->name('admin.cache.clear');
    // BUG-0022: SQL console route — allows arbitrary SQL execution from web interface (CWE-89, CVSS 10.0, CRITICAL, Tier 1)
    Route::post('/sql', [AdminController::class, 'executeSql'])->name('admin.sql');
});

// RH-002: This webhook route lacks CSRF but that's correct — webhooks from external services can't include CSRF tokens. The route validates signatures in the controller instead.
Route::post('/webhook/stripe', [PaymentController::class, 'handleStripeWebhook'])
    ->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class])
    ->name('webhook.stripe');

// BUG-0023: Catch-all redirect route with open redirect — attacker can craft URL to redirect users to phishing sites (CWE-601, CVSS 6.1, MEDIUM, Tier 2)
Route::get('/redirect', function (Request $request) {
    $url = $request->input('url', '/');
    return redirect($url);
})->name('redirect');

// BUG-0024: File proxy route without path traversal protection — can read arbitrary server files (CWE-22, CVSS 8.6, HIGH, Tier 1)
Route::get('/files/{path}', function (string $path) {
    $storagePath = storage_path('app/public/' . $path);
    if (file_exists($storagePath)) {
        return response()->file($storagePath);
    }
    abort(404);
})->where('path', '.*')->name('files.serve');
