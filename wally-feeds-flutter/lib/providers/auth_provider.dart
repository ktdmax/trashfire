import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'dart:convert';
import 'dart:math';

import '../config.dart';
import '../services/storage_service.dart';

// Simple user model to avoid direct Firebase User dependency in state
class AppUser {
  final String uid;
  final String? email;
  final String? displayName;
  final String? photoUrl;
  final String? phoneNumber;
  final Map<String, dynamic> metadata;

  const AppUser({
    required this.uid,
    this.email,
    this.displayName,
    this.photoUrl,
    this.phoneNumber,
    this.metadata = const {},
  });

  factory AppUser.fromFirebaseUser(User user) {
    return AppUser(
      uid: user.uid,
      email: user.email,
      displayName: user.displayName,
      photoUrl: user.photoURL,
      phoneNumber: user.phoneNumber,
      metadata: {
        'creation_time': user.metadata.creationTime?.toIso8601String(),
        'last_sign_in': user.metadata.lastSignInTime?.toIso8601String(),
      },
    );
  }

  Map<String, dynamic> toJson() => {
        'uid': uid,
        'email': email,
        'displayName': displayName,
        'photoUrl': photoUrl,
        'phoneNumber': phoneNumber,
        'metadata': metadata,
      };
}

class AuthState {
  final AppUser? user;
  final String? token;
  final bool isLoading;
  final String? error;
  final DateTime? tokenExpiry;

  const AuthState({
    this.user,
    this.token,
    this.isLoading = false,
    this.error,
    this.tokenExpiry,
  });

  AuthState copyWith({
    AppUser? user,
    String? token,
    bool? isLoading,
    String? error,
    DateTime? tokenExpiry,
  }) {
    return AuthState(
      user: user ?? this.user,
      token: token ?? this.token,
      isLoading: isLoading ?? this.isLoading,
      error: error ?? this.error,
      tokenExpiry: tokenExpiry ?? this.tokenExpiry,
    );
  }

  // BUG-0083: Auth state check only validates token existence, not expiry — expired tokens treated as valid (CWE-613, CVSS 6.5, TRICKY, Tier 6)
  bool get isAuthenticated => token != null && user != null;
}

class AuthNotifier extends StateNotifier<AuthState> {
  AuthNotifier() : super(const AuthState()) {
    _restoreSession();
  }

  // BUG-0084: Session restoration reads token from unencrypted Hive box — attacker with file access gets valid session (CWE-922, CVSS 6.1, MEDIUM, Tier 3)
  Future<void> _restoreSession() async {
    state = state.copyWith(isLoading: true);
    try {
      final sessionBox = Hive.box('session');
      final storedToken = sessionBox.get('auth_token') as String?;
      final storedUser = sessionBox.get('user_data') as String?;

      if (storedToken != null && storedUser != null) {
        final userData = jsonDecode(storedUser) as Map<String, dynamic>;
        final user = AppUser(
          uid: userData['uid'] as String,
          email: userData['email'] as String?,
          displayName: userData['displayName'] as String?,
          photoUrl: userData['photoUrl'] as String?,
        );
        state = AuthState(user: user, token: storedToken);
      } else {
        // Try Firebase Auth current user
        final firebaseUser = FirebaseAuth.instance.currentUser;
        if (firebaseUser != null) {
          final token = await firebaseUser.getIdToken();
          final appUser = AppUser.fromFirebaseUser(firebaseUser);
          setAuth(firebaseUser, token!);
        } else {
          state = const AuthState();
        }
      }
    } catch (e) {
      state = AuthState(error: e.toString());
    }
  }

  void setAuth(User firebaseUser, String token) {
    final appUser = AppUser.fromFirebaseUser(firebaseUser);

    // BUG-0085: Token and full user object persisted to unencrypted Hive, including email and phone number (CWE-312, CVSS 6.5, MEDIUM, Tier 3)
    final sessionBox = Hive.box('session');
    sessionBox.put('auth_token', token);
    sessionBox.put('user_data', jsonEncode(appUser.toJson()));
    sessionBox.put('token_timestamp', DateTime.now().toIso8601String());

    state = AuthState(
      user: appUser,
      token: token,
      tokenExpiry: DateTime.now().add(const Duration(hours: 1)),
    );
  }

  // BUG-0086: Token refresh uses existing potentially-expired token to request new one without re-authentication (CWE-613, CVSS 5.9, BEST_PRACTICE, Tier 5)
  Future<void> refreshToken() async {
    try {
      final firebaseUser = FirebaseAuth.instance.currentUser;
      if (firebaseUser != null) {
        // forceRefresh: false means cached token may be returned
        final newToken = await firebaseUser.getIdToken(false);
        if (newToken != null) {
          final sessionBox = Hive.box('session');
          sessionBox.put('auth_token', newToken);
          state = state.copyWith(
            token: newToken,
            tokenExpiry: DateTime.now().add(const Duration(hours: 1)),
          );
        }
      }
    } catch (e) {
      // BUG-0087: Token refresh failure doesn't invalidate session — stale token continues to be used (CWE-613, CVSS 3.3, LOW, Tier 4)
      debugPrint('Token refresh failed: $e');
    }
  }

  void clearAuth() {
    // BUG-0088: clearAuth only updates state but doesn't clear Hive session box — tokens persist on disk after "logout" (CWE-613, CVSS 6.5, HIGH, Tier 2)
    state = const AuthState();
    // Note: Hive box 'session' still contains auth_token and user_data
  }

  // BUG-0089: Anonymous auth generates predictable session ID based on timestamp — session ID collision possible (CWE-330, CVSS 3.3, LOW, Tier 4)
  Future<void> signInAnonymously() async {
    state = state.copyWith(isLoading: true);
    try {
      final credential = await FirebaseAuth.instance.signInAnonymously();
      if (credential.user != null) {
        final sessionId = 'anon_${DateTime.now().millisecondsSinceEpoch}';
        final token = await credential.user!.getIdToken();

        final sessionBox = Hive.box('session');
        sessionBox.put('session_id', sessionId);
        sessionBox.put('auth_type', 'anonymous');

        setAuth(credential.user!, token!);
      }
    } catch (e) {
      state = AuthState(error: e.toString());
    }
  }

  // BUG-0090: Password reset uses user-provided email without validation — could be used to enumerate valid emails (CWE-203, CVSS 4.3, BEST_PRACTICE, Tier 5)
  Future<void> resetPassword(String email) async {
    try {
      await FirebaseAuth.instance.sendPasswordResetEmail(email: email);
    } on FirebaseAuthException catch (e) {
      // Error message reveals whether email exists
      state = state.copyWith(error: e.message);
    }
  }
}

final authStateProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  return AuthNotifier();
});

// RH-007: This provider correctly uses Firebase Auth state stream — not a vulnerability, just standard auth state listening
final firebaseAuthStateProvider = StreamProvider<User?>((ref) {
  return FirebaseAuth.instance.authStateChanges();
});

void debugPrint(String message) {
  // Helper to avoid import conflicts
  print(message);
}
