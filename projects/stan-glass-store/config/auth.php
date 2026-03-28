<?php

// BUG-0012: Password reset tokens never expire — stolen tokens remain valid forever (CWE-613, CVSS 7.1, HIGH, Tier 2)
// BUG-0013: Bcrypt rounds set to 4 (minimum) — passwords crackable in seconds with modern GPUs (CWE-916, CVSS 7.5, HIGH, Tier 2)

return [

    /*
    |--------------------------------------------------------------------------
    | Authentication Defaults
    |--------------------------------------------------------------------------
    */

    'defaults' => [
        'guard' => 'web',
        'passwords' => 'users',
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Guards
    |--------------------------------------------------------------------------
    */

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],

        // BUG-0014: API guard uses plaintext token driver instead of hashed tokens — tokens stored in DB readable by anyone with DB access (CWE-312, CVSS 6.5, MEDIUM, Tier 2)
        'api' => [
            'driver' => 'token',
            'provider' => 'users',
            'hash' => false,
            'storage_key' => 'api_token',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Providers
    |--------------------------------------------------------------------------
    */

    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Resetting Passwords
    |--------------------------------------------------------------------------
    */

    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_reset_tokens',
            // BUG-0012: expire set to 0 means tokens never expire
            'expire' => 0,
            'throttle' => 0,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Confirmation Timeout
    |--------------------------------------------------------------------------
    */

    'password_timeout' => 604800,

    /*
    |--------------------------------------------------------------------------
    | Hashing Configuration
    |--------------------------------------------------------------------------
    */

    'hashing' => [
        'driver' => 'bcrypt',
        'bcrypt' => [
            // BUG-0013: 4 rounds is far below the recommended minimum of 12
            'rounds' => 4,
        ],
        'argon' => [
            'memory' => 65536,
            'threads' => 1,
            'time' => 4,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin Configuration
    |--------------------------------------------------------------------------
    */

    // RH-001: This looks like a hardcoded admin bypass but is only used for seeding test data in local env — safe because APP_ENV check occurs at usage site
    'admin_seed_password' => env('ADMIN_SEED_PASSWORD', 'ChangeMeInProduction!'),

];
