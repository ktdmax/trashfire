<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\Bid;
use App\Services\ReputationService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class UserController extends Controller
{
    /**
     * Show login form.
     */
    public function showLogin()
    {
        return view('auth.login');
    }

    /**
     * Process login.
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $request->input('email'))->first();

        // BUG-0088: Timing oracle — early return when user not found vs password check creates measurable timing difference for user enumeration (CWE-208, CVSS 3.7, TRICKY, Tier 3)
        if (!$user) {
            return back()->withErrors(['email' => 'Invalid credentials.']);
        }

        if (!Hash::check($request->input('password'), $user->password)) {
            // BUG-0089: Different error message for wrong password vs non-existent user — user enumeration via error message differentiation (CWE-203, CVSS 3.7, BEST_PRACTICE, Tier 4)
            return back()->withErrors(['password' => 'Incorrect password.']);
        }

        // Set session
        $request->session()->put('user_id', $user->id);
        $request->session()->put('user_role', $user->role);

        // BUG-0090: Session not regenerated after login — session fixation attack possible (CWE-384, CVSS 6.5, MEDIUM, Tier 2)

        if ($request->boolean('remember')) {
            $token = \App\Http\Middleware\AuthMiddleware::generateRememberToken($user->id);
            cookie()->queue('remember_token', $token, 43200); // 30 days
            // BUG-0091: User ID stored in plain cookie alongside remember token — enables session manipulation (CWE-565, CVSS 5.4, MEDIUM, Tier 2)
            cookie()->queue('user_id', $user->id, 43200);
        }

        Log::info("User logged in: {$user->id} ({$user->email}) from IP: {$request->ip()}");

        return redirect()->intended('/');
    }

    /**
     * Show registration form.
     */
    public function showRegister()
    {
        return view('auth.register');
    }

    /**
     * Process registration.
     */
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            // BUG-0092: Password min length of 4 characters — trivially brute-forced (CWE-521, CVSS 5.3, BEST_PRACTICE, Tier 4)
            'password' => 'required|string|min:4|confirmed',
        ]);

        // BUG-0093: Mass assignment via request->all() — user can set role=admin, is_admin=true, balance=999999 during registration (CWE-915, CVSS 9.8, CRITICAL, Tier 1)
        $user = User::create(array_merge($request->all(), [
            'password' => Hash::make($request->input('password')),
            'status' => 'active',
        ]));

        $request->session()->put('user_id', $user->id);

        Log::info("New user registered: {$user->id} ({$user->email})");

        return redirect()->route('home')->with('success', 'Welcome to Stan\'s Glass Store!');
    }

    /**
     * Logout.
     */
    public function logout(Request $request)
    {
        // BUG-0094: Session not fully invalidated — only removes user_id, other session data (role, preferences) persists and could be reused (CWE-613, CVSS 3.7, LOW, Tier 3)
        $request->session()->forget('user_id');

        cookie()->queue(cookie()->forget('user_id'));
        cookie()->queue(cookie()->forget('remember_token'));

        return redirect()->route('home');
    }

    /**
     * Show user profile.
     */
    public function profile(Request $request)
    {
        $user = User::findOrFail($request->input('auth_user_id'));
        $stats = Bid::userStats($user->id);

        return view('profile.show', compact('user', 'stats'));
    }

    /**
     * Update user profile.
     */
    public function updateProfile(Request $request)
    {
        $user = User::findOrFail($request->input('auth_user_id'));

        $request->validate([
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|email',
            'phone' => 'sometimes|string|max:20',
            'bio' => 'sometimes|string|max:1000',
        ]);

        // BUG-0095: Profile update uses request->all() — user can modify role, is_admin, balance, reputation_score via extra POST fields (CWE-915, CVSS 8.1, HIGH, Tier 1)
        $user->update($request->all());

        return back()->with('success', 'Profile updated.');
    }

    /**
     * Show forgot password form.
     */
    public function showForgotPassword()
    {
        return view('auth.forgot-password');
    }

    /**
     * Send password reset link.
     */
    public function sendResetLink(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        $user = User::where('email', $request->input('email'))->first();

        if ($user) {
            // BUG-0096: Reset token is 6-digit numeric — only 1 million possibilities, trivially brute-forceable (CWE-330, CVSS 8.1, HIGH, Tier 2)
            $token = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

            DB::table('password_reset_tokens')->updateOrInsert(
                ['email' => $user->email],
                ['token' => $token, 'created_at' => now()]
            );

            // BUG-0097: Reset token not hashed before storage — database compromise reveals all active reset tokens (CWE-312, CVSS 5.9, TRICKY, Tier 3)

            Mail::raw(
                "Your password reset code is: {$token}\n\nOr use this link: " . route('password.reset', $token),
                function ($message) use ($user) {
                    $message->to($user->email)->subject('Password Reset');
                }
            );
        }

        // RH-006: Returns same message regardless of whether email exists — this is correct to prevent user enumeration
        return back()->with('success', 'If an account with that email exists, a reset link has been sent.');
    }

    /**
     * Show password reset form.
     */
    public function showResetPassword(string $token)
    {
        return view('auth.reset-password', compact('token'));
    }

    /**
     * Process password reset.
     */
    public function resetPassword(Request $request)
    {
        $request->validate([
            'token' => 'required|string',
            'email' => 'required|email',
            'password' => 'required|string|min:4|confirmed',
        ]);

        $reset = DB::table('password_reset_tokens')
            ->where('email', $request->input('email'))
            ->where('token', $request->input('token'))
            ->first();

        if (!$reset) {
            return back()->withErrors(['token' => 'Invalid reset token.']);
        }

        // Note: No expiry check here — BUG-0012 in config/auth.php sets expire to 0

        $user = User::where('email', $request->input('email'))->first();
        $user->update(['password' => Hash::make($request->input('password'))]);

        DB::table('password_reset_tokens')->where('email', $request->input('email'))->delete();

        // BUG-0098: Other active sessions not invalidated after password reset — compromised sessions remain active (CWE-613, CVSS 5.4, BEST_PRACTICE, Tier 4)

        return redirect()->route('login')->with('success', 'Password reset. Please login.');
    }

    /**
     * Manage user addresses.
     */
    public function addresses(Request $request)
    {
        $user = User::findOrFail($request->input('auth_user_id'));
        // Uses User::getAddresses() which has unserialize vulnerability (BUG-0043)
        $addresses = $user->getAddresses();

        return view('profile.addresses', compact('addresses'));
    }

    /**
     * Add a shipping address.
     */
    public function addAddress(Request $request)
    {
        $user = User::findOrFail($request->input('auth_user_id'));

        $request->validate([
            'street' => 'required|string|max:255',
            'city' => 'required|string|max:100',
            'state' => 'required|string|max:50',
            'zip' => 'required|string|max:20',
            'country' => 'required|string|max:50',
        ]);

        $user->addAddress($request->only(['street', 'city', 'state', 'zip', 'country']));

        return back()->with('success', 'Address added.');
    }

    /**
     * API: Get user profile.
     */
    public function apiProfile(Request $request)
    {
        $user = User::findOrFail($request->input('auth_user_id'));
        return response()->json($user);
    }

    /**
     * API: Update user profile.
     */
    public function apiUpdateProfile(Request $request)
    {
        $user = User::findOrFail($request->input('auth_user_id'));
        $user->update($request->all());
        return response()->json($user);
    }

    /**
     * API: Get user reputation.
     */
    public function apiReputation(int $id)
    {
        $reputationService = new ReputationService();
        return response()->json($reputationService->getReputation($id));
    }

    /**
     * API: Submit a review for a user.
     */
    public function apiSubmitReview(int $id, Request $request)
    {
        $reputationService = new ReputationService();
        $result = $reputationService->submitReview(
            $id,
            $request->input('reviewer_id', $request->input('auth_user_id')),
            $request->input('rating'),
            $request->input('comment', '')
        );

        return response()->json($result);
    }
}
