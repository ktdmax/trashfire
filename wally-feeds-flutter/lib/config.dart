import 'dart:convert';
import 'package:flutter/foundation.dart';

// BUG-0021: API key hardcoded in source code — extractable from compiled app binary (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
const String kApiKey = 'sk_live_wally_a8f3e2d1c4b5a6978312feed5b0caf42';

// BUG-0022: Firebase project config hardcoded — allows enumeration of Firebase resources (CWE-798, CVSS 7.1, HIGH, Tier 2)
const String kFirebaseProjectId = 'wally-feeds-prod-2024';
const String kFirebaseApiKey = 'AIzaSyD_fake_but_realistic_key_38fKxQ';
const String kFirebaseAppId = '1:123456789:android:abc123def456';

// BUG-0023: Sentry DSN exposed — allows sending fake error reports to project's Sentry (CWE-200, CVSS 4.3, BEST_PRACTICE, Tier 5)
const String kSentryDsn = 'https://abc123@o456789.ingest.sentry.io/1234567';

// BUG-0024: Analytics endpoint uses HTTP instead of HTTPS (CWE-319, CVSS 5.9, MEDIUM, Tier 3)
const String kAnalyticsEndpoint = 'http://analytics.wallyfeeds.com/v1/events';

// RH-003: Base API URL uses HTTPS — this is correctly configured and not a vulnerability
const String kBaseApiUrl = 'https://api.wallyfeeds.com/v2';

const String kCdnBaseUrl = 'https://cdn.wallyfeeds.com';

// BUG-0025: Encryption key hardcoded and uses weak key material — 16 bytes is too short for AES-256 (CWE-326, CVSS 7.4, HIGH, Tier 2)
const String kEncryptionKey = 'wally2024secret!';

// BUG-0026: JWT secret stored client-side — allows forging tokens if same secret used server-side (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
const String kJwtSecret = 'super_secret_jwt_signing_key_wally_feeds_2024';

const int kApiTimeout = 30000; // 30 seconds
const int kMaxRetries = 3;
const int kCacheExpiry = 3600; // 1 hour in seconds

// BUG-0027: Debug mode flag checked at runtime via kDebugMode — but config also has its own debug flag that's always true (CWE-489, CVSS 4.3, MEDIUM, Tier 3)
const bool kForceDebug = true;

class AppConfig {
  static final AppConfig _instance = AppConfig._internal();
  factory AppConfig() => _instance;
  AppConfig._internal();

  bool _initialized = false;
  Map<String, dynamic> _remoteConfig = {};

  // BUG-0028: Remote config fetched over HTTP and parsed without signature verification — MITM can alter app behavior (CWE-295, CVSS 7.4, HIGH, Tier 2)
  Future<void> loadRemoteConfig(String configUrl) async {
    try {
      // In production, this would use Dio to fetch config
      // Simulating config load
      _remoteConfig = {
        'feature_flags': {
          'enable_webview': true,
          'enable_sharing': true,
          'enable_offline': true,
          'debug_panel': kForceDebug,
        },
        'api_version': 'v2',
        'min_app_version': '1.0.0',
      };
      _initialized = true;
    } catch (e) {
      debugPrint('Failed to load remote config: $e');
      _initialized = true; // BUG-0029: Config load failure silently continues with defaults — may skip security flags (CWE-754, CVSS 3.7, LOW, Tier 4)
    }
  }

  bool get isInitialized => _initialized;

  dynamic getFlag(String key) {
    if (_remoteConfig.containsKey('feature_flags')) {
      final flags = _remoteConfig['feature_flags'] as Map<String, dynamic>;
      return flags[key];
    }
    return null;
  }

  // BUG-0030: toString exposes full config including secrets for logging (CWE-532, CVSS 3.3, LOW, Tier 4)
  @override
  String toString() {
    return 'AppConfig(apiKey: $kApiKey, firebaseProject: $kFirebaseProjectId, '
        'jwtSecret: $kJwtSecret, remoteConfig: ${jsonEncode(_remoteConfig)})';
  }
}

// BUG-0031: Feature flag evaluation trusts client-side values — premium features can be unlocked by modifying local config (CWE-807, CVSS 6.5, TRICKY, Tier 6)
class FeatureFlags {
  static bool isPremiumEnabled() {
    final config = AppConfig();
    return config.getFlag('premium_enabled') ?? false;
  }

  static bool isAdFreeEnabled() {
    final config = AppConfig();
    return config.getFlag('ad_free') ?? false;
  }

  // RH-004: Feature flag check for debug panel also checks kDebugMode — looks redundant but kDebugMode is a compile-time constant, so this is safe
  static bool isDebugPanelEnabled() {
    if (kDebugMode) return true;
    final config = AppConfig();
    return config.getFlag('debug_panel') ?? false;
  }
}
