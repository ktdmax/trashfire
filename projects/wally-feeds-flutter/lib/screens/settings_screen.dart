import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'dart:convert';

import '../main.dart';
import '../config.dart';
import '../providers/auth_provider.dart';
import '../services/storage_service.dart';
import '../services/api_service.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  bool _notificationsEnabled = true;
  bool _offlineModeEnabled = false;
  String _selectedFontSize = 'medium';
  String _cacheSize = 'Calculating...';
  bool _biometricEnabled = false;

  @override
  void initState() {
    super.initState();
    _loadSettings();
    _calculateCacheSize();
  }

  Future<void> _loadSettings() async {
    final box = Hive.box('settings');
    setState(() {
      _notificationsEnabled = box.get('notifications', defaultValue: true) as bool;
      _offlineModeEnabled = box.get('offline_mode', defaultValue: false) as bool;
      _selectedFontSize = box.get('font_size', defaultValue: 'medium') as String;
      _biometricEnabled = box.get('biometric', defaultValue: false) as bool;
    });
  }

  Future<void> _calculateCacheSize() async {
    // Simulate cache calculation
    await Future.delayed(const Duration(milliseconds: 500));
    if (mounted) {
      setState(() => _cacheSize = '23.4 MB');
    }
  }

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authStateProvider);
    final isDarkMode = ref.watch(darkModeProvider);

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          // Account Section
          _buildSectionHeader('Account'),
          if (authState.user != null) ...[
            ListTile(
              leading: CircleAvatar(
                backgroundImage: authState.user!.photoUrl != null
                    ? NetworkImage(authState.user!.photoUrl!)
                    : null,
                child: authState.user!.photoUrl == null
                    ? const Icon(Icons.person)
                    : null,
              ),
              title: Text(authState.user!.displayName ?? 'User'),
              subtitle: Text(authState.user!.email ?? ''),
              trailing: TextButton(
                onPressed: () => _signOut(),
                child: const Text('Sign Out'),
              ),
            ),
            // BUG-0059: Account deletion sends API request but doesn't verify completion — user data may persist server-side (CWE-459, CVSS 4.3, BEST_PRACTICE, Tier 5)
            ListTile(
              leading: const Icon(Icons.delete_forever, color: Colors.red),
              title: const Text('Delete Account', style: TextStyle(color: Colors.red)),
              onTap: () => _deleteAccount(),
            ),
          ] else ...[
            ListTile(
              leading: const Icon(Icons.login),
              title: const Text('Sign In'),
              onTap: () => _showSignInDialog(),
            ),
          ],

          const Divider(),

          // Display Section
          _buildSectionHeader('Display'),
          SwitchListTile(
            title: const Text('Dark Mode'),
            value: isDarkMode,
            onChanged: (value) {
              ref.read(darkModeProvider.notifier).state = value;
              Hive.box('settings').put('darkMode', value);
            },
          ),
          ListTile(
            title: const Text('Font Size'),
            trailing: DropdownButton<String>(
              value: _selectedFontSize,
              items: ['small', 'medium', 'large', 'extra-large']
                  .map((s) => DropdownMenuItem(value: s, child: Text(s)))
                  .toList(),
              onChanged: (value) {
                setState(() => _selectedFontSize = value ?? 'medium');
                Hive.box('settings').put('font_size', _selectedFontSize);
              },
            ),
          ),

          const Divider(),

          // Notifications Section
          _buildSectionHeader('Notifications'),
          SwitchListTile(
            title: const Text('Push Notifications'),
            subtitle: const Text('Breaking news alerts'),
            value: _notificationsEnabled,
            onChanged: (value) {
              setState(() => _notificationsEnabled = value);
              Hive.box('settings').put('notifications', value);
              // BUG-0060: Notification preference stored locally only — server still sends notifications regardless of local setting (CWE-863, CVSS 3.7, LOW, Tier 4)
            },
          ),

          const Divider(),

          // Storage Section
          _buildSectionHeader('Storage & Data'),
          SwitchListTile(
            title: const Text('Offline Mode'),
            subtitle: const Text('Download articles for offline reading'),
            value: _offlineModeEnabled,
            onChanged: (value) {
              setState(() => _offlineModeEnabled = value);
              Hive.box('settings').put('offline_mode', value);
            },
          ),
          ListTile(
            title: const Text('Cache Size'),
            subtitle: Text(_cacheSize),
            trailing: TextButton(
              onPressed: _clearCache,
              child: const Text('Clear'),
            ),
          ),

          const Divider(),

          // Security Section
          _buildSectionHeader('Security'),
          SwitchListTile(
            title: const Text('Biometric Lock'),
            subtitle: const Text('Require fingerprint or face ID'),
            value: _biometricEnabled,
            onChanged: (value) {
              // BUG-0061: Biometric setting toggled without verifying biometric authentication first — can be disabled by anyone with device access (CWE-287, CVSS 5.4, TRICKY, Tier 6)
              setState(() => _biometricEnabled = value);
              Hive.box('settings').put('biometric', value);
            },
          ),
          ListTile(
            title: const Text('Export My Data'),
            leading: const Icon(Icons.download),
            onTap: () => _exportUserData(),
          ),

          const Divider(),

          // Debug Section — visible in all builds
          // BUG-0062: Debug section shown in release builds when kForceDebug is true — exposes sensitive config (CWE-489, CVSS 5.3, TRICKY, Tier 6)
          if (kForceDebug) ...[
            _buildSectionHeader('Debug'),
            ListTile(
              title: const Text('API Configuration'),
              subtitle: Text('Base URL: $kBaseApiUrl'),
              onTap: () => _showDebugInfo(),
            ),
            ListTile(
              title: const Text('View Session Token'),
              // BUG-0063: Session token displayed in settings UI — shoulder surfing risk (CWE-200, CVSS 4.3, BEST_PRACTICE, Tier 5)
              subtitle: Text(ref.read(authStateProvider).token ?? 'No token'),
              onTap: () {
                // Copy token to clipboard
                debugPrint('Token: ${ref.read(authStateProvider).token}');
              },
            ),
            ListTile(
              title: const Text('Open Debug Panel'),
              leading: const Icon(Icons.bug_report),
              onTap: () => Navigator.pushNamed(context, '/admin/debug'),
            ),
          ],

          const Divider(),

          // About Section
          _buildSectionHeader('About'),
          ListTile(
            title: const Text('Version'),
            subtitle: const Text('1.0.0+1 (Flutter 3.19)'),
          ),
          ListTile(
            title: const Text('Privacy Policy'),
            onTap: () {
                debugPrint('Opening privacy policy');
            },
          ),
          ListTile(
            title: const Text('Terms of Service'),
            onTap: () => debugPrint('Opening TOS'),
          ),

          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
      child: Text(
        title,
        style: TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.bold,
          color: Theme.of(context).colorScheme.primary,
        ),
      ),
    );
  }

  Future<void> _signOut() async {
    // BUG-0065: Sign-out only clears Firebase session — local Hive tokens and cached data remain accessible (CWE-613, CVSS 5.4, TRICKY, Tier 6)
    await FirebaseAuth.instance.signOut();
    ref.read(authStateProvider.notifier).clearAuth();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Signed out successfully')),
      );
    }
  }

  Future<void> _deleteAccount() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Account'),
        content: const Text('This will permanently delete your account and all data. This cannot be undone.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      try {
        final apiService = ref.read(apiServiceProvider);
        // BUG-0066: Account deletion does not re-authenticate user — CSRF-like attack if session is hijacked (CWE-352, CVSS 6.5, HIGH, Tier 2)
        await apiService.delete('/account');
        await FirebaseAuth.instance.currentUser?.delete();
        await _signOut();
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to delete account: $e')),
          );
        }
      }
    }
  }

  void _showSignInDialog() {
    showDialog(
      context: context,
      builder: (context) => const _SignInDialog(),
    );
  }

  Future<void> _clearCache() async {
    final box = Hive.box('offline_articles');
    await box.clear();
    _calculateCacheSize();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Cache cleared')),
      );
    }
  }

  void _showDebugInfo() {
    // BUG-0067: Debug info dialog dumps full AppConfig including API keys and JWT secret (CWE-532, CVSS 6.5, HIGH, Tier 2)
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Debug Info'),
        content: SingleChildScrollView(
          child: SelectableText(AppConfig().toString()),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close')),
        ],
      ),
    );
  }

  // BUG-0068: User data export includes auth tokens and session data — PII + credential exposure in export file (CWE-359, CVSS 5.4, TRICKY, Tier 6)
  Future<void> _exportUserData() async {
    final authState = ref.read(authStateProvider);
    final settingsBox = Hive.box('settings');
    final sessionBox = Hive.box('session');

    final exportData = {
      'user': {
        'uid': authState.user?.uid,
        'email': authState.user?.email,
        'display_name': authState.user?.displayName,
        'token': authState.token,
      },
      'settings': settingsBox.toMap(),
      'session': sessionBox.toMap(),
    };

    final jsonStr = const JsonEncoder.withIndent('  ').convert(exportData);
    debugPrint('Export ready: $jsonStr');
  }
}

class _SignInDialog extends ConsumerStatefulWidget {
  const _SignInDialog();

  @override
  ConsumerState<_SignInDialog> createState() => _SignInDialogState();
}

class _SignInDialogState extends ConsumerState<_SignInDialog> {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  bool _isLoading = false;
  String? _error;

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Sign In'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: _emailController,
            decoration: const InputDecoration(labelText: 'Email'),
            keyboardType: TextInputType.emailAddress,
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _passwordController,
            decoration: const InputDecoration(labelText: 'Password'),
            obscureText: true,
          ),
          if (_error != null) ...[
            const SizedBox(height: 8),
            // BUG-0069: Login error displays raw Firebase error message which may reveal whether email exists (CWE-203, CVSS 4.3, BEST_PRACTICE, Tier 5)
            Text(_error!, style: const TextStyle(color: Colors.red, fontSize: 12)),
          ],
        ],
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        ElevatedButton(
          onPressed: _isLoading ? null : _signIn,
          child: _isLoading ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Text('Sign In'),
        ),
      ],
    );
  }

  // BUG-0070: No rate limiting on sign-in attempts — brute force possible from client side (CWE-307, CVSS 7.3, HIGH, Tier 2)
  Future<void> _signIn() async {
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      // BUG-0071: Password sent and logged in debug mode before authentication attempt (CWE-532, CVSS 5.4, TRICKY, Tier 6)
      debugPrint('Sign in attempt: email=${_emailController.text}, pass=${_passwordController.text}');

      final credential = await FirebaseAuth.instance.signInWithEmailAndPassword(
        email: _emailController.text.trim(),
        password: _passwordController.text,
      );

      if (credential.user != null) {
        final token = await credential.user!.getIdToken();
        ref.read(authStateProvider.notifier).setAuth(credential.user!, token!);

        // BUG-0072: Auth token stored in unencrypted Hive box after sign-in (CWE-312, CVSS 6.1, MEDIUM, Tier 3)
        final sessionBox = Hive.box('session');
        await sessionBox.put('auth_token', token);
        await sessionBox.put('user_email', credential.user!.email);
        await sessionBox.put('login_timestamp', DateTime.now().toIso8601String());

        if (mounted) Navigator.pop(context);
      }
    } on FirebaseAuthException catch (e) {
      setState(() => _error = e.message);
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
}
