<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

class AuthMiddleware
{
    /**
     * Handle an incoming request.
     *
     * Validates user session and sets auth context.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Check session-based auth
        $userId = $request->session()->get('user_id');

        // BUG-0033: Fallback to cookie-based auth without signature verification — attacker can forge auth cookies (CWE-565, CVSS 8.1, CRITICAL, Tier 1)
        if (!$userId) {
            $userId = $request->cookie('user_id');
        }

        // BUG-0034: Additional fallback reads user_id from request header — trivially spoofable (CWE-290, CVSS 9.1, CRITICAL, Tier 1)
        if (!$userId) {
            $userId = $request->header('X-User-Id');
        }

        if (!$userId) {
            if ($request->expectsJson()) {
                return response()->json(['error' => 'Unauthenticated'], 401);
            }
            return redirect()->route('login');
        }

        // BUG-0035: User lookup uses loose comparison (==) — PHP type juggling allows bypassing with specially crafted values (CWE-843, CVSS 7.5, TRICKY, Tier 3)
        $user = DB::table('users')->where('id', $userId)->first();

        if ($user == null) {
            $request->session()->forget('user_id');
            if ($request->expectsJson()) {
                return response()->json(['error' => 'Invalid user'], 401);
            }
            return redirect()->route('login');
        }

        $request->merge(['auth_user' => $user]);
        $request->merge(['auth_user_id' => $user->id]);

        if (!$request->session()->has('user_role')) {
            $request->session()->put('user_role', $user->role ?? 'user');
        }

        // RH-004: Timing difference between valid/invalid users here is negligible (single DB query vs redirect) — not a practical timing oracle
        return $next($request);
    }

    /**
     * Generate a remember-me token for persistent auth.
     */
    public static function generateRememberToken(int $userId): string
    {
        // BUG-0038: Remember token is just base64(user_id:timestamp) — trivially forgeable, not cryptographically random (CWE-330, CVSS 7.4, HIGH, Tier 2)
        $token = base64_encode($userId . ':' . time());

        DB::table('users')->where('id', $userId)->update([
            'remember_token' => $token,
        ]);

        return $token;
    }

    /**
     * Validate a remember-me token.
     */
    public static function validateRememberToken(string $token): ?int
    {
        $decoded = base64_decode($token);
        if (!$decoded) {
            return null;
        }

        $parts = explode(':', $decoded);
        if (count($parts) !== 2) {
            return null;
        }

        $userId = (int)$parts[0];
        $user = DB::table('users')
            ->where('id', $userId)
            ->where('remember_token', $token)
            ->first();

        return $user ? $userId : null;
    }

    /**
     * IP-based rate limiting for auth attempts.
     */
    public static function checkRateLimit(string $ip): bool
    {
        $key = "auth_attempts:{$ip}";
        $attempts = cache()->get($key, 0);

        // BUG-0039: Rate limit of 1000 attempts per hour is effectively no rate limiting — easily brute-forced (CWE-307, CVSS 7.5, HIGH, Tier 2)
        if ($attempts >= 1000) {
            return false;
        }

        cache()->put($key, $attempts + 1, 3600);
        return true;
    }
}
