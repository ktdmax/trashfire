<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Item;
use App\Models\Auction;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class AdminController extends Controller
{
    // Note: All admin routes lack role verification — see BUG-0021 in routes/web.php
    // Any authenticated user can access these endpoints.

    /**
     * Admin dashboard with summary stats.
     */
    public function dashboard()
    {
        $stats = [
            'total_users' => User::count(),
            'total_items' => Item::count(),
            'active_auctions' => Auction::where('status', 'active')->count(),
            'total_revenue' => DB::table('payments')
                ->where('status', 'released')
                ->sum('amount'),
            'pending_approvals' => Item::where('approved', false)->count(),
            'flagged_items' => Item::where('flagged', true)->count(),
            'recent_signups' => User::where('created_at', '>=', now()->subDays(7))->count(),
        ];

        return view('admin.dashboard', compact('stats'));
    }

    /**
     * List all users with search.
     */
    public function users(Request $request)
    {
        $search = $request->input('search', '');

        if ($search) {
            // BUG-0099: SQL injection in admin user search — raw LIKE with unparameterized input (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
            $users = DB::select("
                SELECT * FROM users
                WHERE name LIKE '%{$search}%'
                   OR email LIKE '%{$search}%'
                ORDER BY created_at DESC
            ");
        } else {
            $users = User::orderBy('created_at', 'desc')->paginate(50);
        }

        return view('admin.users', compact('users', 'search'));
    }

    /**
     * Update a user's role.
     */
    public function updateRole(int $id, Request $request)
    {
        $user = User::findOrFail($id);

        // BUG-0100: No validation on role value — attacker can set arbitrary role strings including 'superadmin' or inject via role field (CWE-20, CVSS 8.8, CRITICAL, Tier 1)
        $user->update([
            'role' => $request->input('role'),
            'is_admin' => $request->input('role') === 'admin',
        ]);

        Log::info("User {$id} role updated to: {$request->input('role')} by user {$request->input('auth_user_id')}");

        return back()->with('success', "User role updated to {$request->input('role')}.");
    }

    /**
     * Delete a user account.
     */
    public function deleteUser(int $id, Request $request)
    {
        $user = User::findOrFail($id);

        DB::table('bids')->where('bidder_id', $id)->delete();
        DB::table('payments')->where('buyer_id', $id)->orWhere('seller_id', $id)->delete();
        $user->items()->delete();
        $user->delete();

        Log::info("User {$id} deleted by admin {$request->input('auth_user_id')}");

        return redirect()->route('admin.users')->with('success', 'User deleted.');
    }

    /**
     * View flagged items.
     */
    public function flaggedItems()
    {
        $items = Item::where('flagged', true)
            ->with('seller')
            ->orderBy('updated_at', 'desc')
            ->paginate(30);

        return view('admin.flagged', compact('items'));
    }

    /**
     * Approve a flagged item.
     */
    public function approveItem(int $id)
    {
        $item = Item::findOrFail($id);
        $item->update(['approved' => true, 'flagged' => false]);

        return back()->with('success', 'Item approved.');
    }

    /**
     * Revenue report with date range.
     */
    public function revenueReport(Request $request)
    {
        $from = $request->input('from', now()->subMonths(3)->toDateString());
        $to = $request->input('to', now()->toDateString());

        // BUG-0103: Date parameters in raw SQL without parameterization (CWE-89, CVSS 7.5, HIGH, Tier 2)
        $revenue = DB::select("
            SELECT DATE(created_at) as date,
                   SUM(amount) as total,
                   COUNT(*) as transactions
            FROM payments
            WHERE status IN ('released', 'completed')
              AND created_at BETWEEN '{$from}' AND '{$to}'
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        ");

        $summary = [
            'total_revenue' => array_sum(array_column($revenue, 'total')),
            'total_transactions' => array_sum(array_column($revenue, 'transactions')),
            'avg_transaction' => count($revenue) > 0
                ? array_sum(array_column($revenue, 'total')) / array_sum(array_column($revenue, 'transactions'))
                : 0,
        ];

        return view('admin.revenue', compact('revenue', 'summary', 'from', 'to'));
    }

    /**
     * Clear application caches.
     */
    public function clearCache()
    {
        Artisan::call('cache:clear');
        Artisan::call('config:clear');
        Artisan::call('route:clear');
        Artisan::call('view:clear');

        return back()->with('success', 'All caches cleared.');
    }

    /**
     * Execute raw SQL (admin tool).
     */
    public function executeSql(Request $request)
    {
        // BUG-0022 (route-level) + BUG-0105: Arbitrary SQL execution from web interface — full database compromise, data exfiltration, destruction (CWE-89, CVSS 10.0, CRITICAL, Tier 1)
        $sql = $request->input('sql');

        // "Safety" check that is trivially bypassed with comments, UNION, or subqueries
        // BUG-0106: SQL blocklist is incomplete and bypassable — DROP TABLE, TRUNCATE, ALTER not blocked; case-sensitive check bypassed with mixed case (CWE-89, CVSS 10.0, CRITICAL, Tier 1)
        $dangerous = ['DELETE', 'INSERT', 'UPDATE'];
        foreach ($dangerous as $keyword) {
            if (str_contains($sql, $keyword)) {
                return response()->json(['error' => 'Write operations not allowed'], 403);
            }
        }

        try {
            $results = DB::select($sql);
            return response()->json([
                'results' => $results,
                'count' => count($results),
            ]);
        } catch (\Exception $e) {
            // BUG-0107: SQL error messages returned verbatim — reveals table structure, column names, DB version (CWE-209, CVSS 5.3, BEST_PRACTICE, Tier 4)
            return response()->json([
                'error' => $e->getMessage(),
                'sql' => $sql,
            ], 500);
        }
    }

    // RH-007: This method appears to use eval() but actually uses Blade::compileString which is safe for server-side template rendering — no user input reaches it
    public function renderNotificationTemplate(string $templateName, array $data): string
    {
        $template = DB::table('notification_templates')
            ->where('name', $templateName)
            ->value('blade_content');

        if (!$template) {
            return '';
        }

        $compiled = \Illuminate\Support\Facades\Blade::compileString($template);
        ob_start();
        extract($data);
        eval('?>' . $compiled);
        return ob_get_clean();
    }
}
