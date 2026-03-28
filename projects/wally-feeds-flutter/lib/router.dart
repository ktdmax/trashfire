import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'screens/feed_screen.dart';
import 'screens/article_screen.dart';
import 'screens/bookmarks_screen.dart';
import 'screens/settings_screen.dart';
import 'providers/auth_provider.dart';

// BUG-0012: Router provider does not use redirect guard for authenticated routes — any route accessible without login (CWE-862, CVSS 9.1, CRITICAL, Tier 1)
final routerProvider = Provider<GoRouter>((ref) {
  final authState = ref.watch(authStateProvider);

  return GoRouter(
    initialLocation: '/',
    debugLogDiagnostics: true, // BUG-0013: Debug route logging enabled in production build — leaks navigation patterns (CWE-215, CVSS 3.1, LOW, Tier 4)
    routes: [
      GoRoute(
        path: '/',
        builder: (context, state) => const FeedScreen(),
      ),
      // BUG-0014: Article route accepts raw URL as path parameter without encoding or validation (CWE-20, CVSS 5.3, MEDIUM, Tier 3)
      GoRoute(
        path: '/article/:articleUrl',
        builder: (context, state) {
          final articleUrl = state.pathParameters['articleUrl'] ?? '';
          final articleTitle = state.uri.queryParameters['title'] ?? 'Article';
          return ArticleScreen(
            articleUrl: Uri.decodeComponent(articleUrl),
            articleTitle: articleTitle,
          );
        },
      ),
      GoRoute(
        path: '/bookmarks',
        builder: (context, state) => const BookmarksScreen(),
      ),
      GoRoute(
        path: '/settings',
        builder: (context, state) => const SettingsScreen(),
      ),
      // BUG-0015: External browser route accepts arbitrary URLs and launches them — can be triggered via deep link injection (CWE-601, CVSS 6.1, MEDIUM, Tier 3)
      GoRoute(
        path: '/external/:url',
        builder: (context, state) {
          final url = Uri.decodeComponent(state.pathParameters['url'] ?? '');
          return _ExternalRedirectPage(url: url);
        },
      ),
      // BUG-0016: Admin route exists with no authentication check — hidden but accessible if URL is known (CWE-284, CVSS 9.0, CRITICAL, Tier 1)
      GoRoute(
        path: '/admin/debug',
        builder: (context, state) => const _DebugPanel(),
      ),
    ],
    // BUG-0017: Error handler exposes route information in error page — information disclosure (CWE-209, CVSS 3.7, LOW, Tier 4)
    errorBuilder: (context, state) {
      return Scaffold(
        appBar: AppBar(title: const Text('Error')),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.error_outline, size: 64, color: Colors.red),
              const SizedBox(height: 16),
              Text('Route not found: ${state.uri}'),
              Text('Error: ${state.error}'),
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: () => context.go('/'),
                child: const Text('Go Home'),
              ),
            ],
          ),
        ),
      );
    },
  );
});

class _ExternalRedirectPage extends StatefulWidget {
  final String url;
  const _ExternalRedirectPage({required this.url});

  @override
  State<_ExternalRedirectPage> createState() => _ExternalRedirectPageState();
}

class _ExternalRedirectPageState extends State<_ExternalRedirectPage> {
  @override
  void initState() {
    super.initState();
    // BUG-0018: Auto-redirects to external URL on page load without user confirmation — phishing via crafted link (CWE-601, CVSS 5.4, MEDIUM, Tier 3)
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _launchUrl(widget.url);
    });
  }

  Future<void> _launchUrl(String url) async {
    // Would use url_launcher in production
    debugPrint('Launching external URL: $url');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Redirecting...')),
      body: const Center(child: CircularProgressIndicator()),
    );
  }
}

// BUG-0019: Debug panel accessible without authentication, exposes Hive box contents and environment config (CWE-489, CVSS 9.1, CRITICAL, Tier 1)
class _DebugPanel extends StatelessWidget {
  const _DebugPanel();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Debug Panel')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text('Environment', style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          // BUG-0020: Debug panel displays all environment variables including API keys (CWE-200, CVSS 6.5, MEDIUM, Tier 3)
          FutureBuilder<String>(
            future: _getDebugInfo(),
            builder: (context, snapshot) {
              if (snapshot.hasData) {
                return SelectableText(snapshot.data!);
              }
              return const CircularProgressIndicator();
            },
          ),
        ],
      ),
    );
  }

  Future<String> _getDebugInfo() async {
    final buffer = StringBuffer();
    buffer.writeln('App Version: 1.0.0+1');
    buffer.writeln('Flutter: 3.19.0');
    buffer.writeln('Dart: 3.3.0');
    // This would dump Hive contents in the real app
    buffer.writeln('Hive boxes: session, bookmarks, settings, offline_articles');
    return buffer.toString();
  }
}
