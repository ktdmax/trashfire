import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'dart:convert';

import '../providers/auth_provider.dart';
import '../providers/feed_provider.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../models/article.dart';
import '../config.dart';

class ArticleScreen extends ConsumerStatefulWidget {
  final String articleUrl;
  final String articleTitle;

  const ArticleScreen({
    super.key,
    required this.articleUrl,
    required this.articleTitle,
  });

  @override
  ConsumerState<ArticleScreen> createState() => _ArticleScreenState();
}

class _ArticleScreenState extends ConsumerState<ArticleScreen> {
  late final WebViewController _webViewController;
  bool _isLoading = true;
  double _progress = 0;
  String? _articleHtml;
  Article? _fullArticle;

  @override
  void initState() {
    super.initState();
    _initWebView();
    _loadArticle();
    _trackArticleView();
  }

  // BUG-0041: WebView initialized with JavaScript enabled and no restrictions on navigation — allows loaded page to execute arbitrary JS and navigate to malicious URLs (CWE-79, CVSS 8.1, CRITICAL, Tier 1)
  void _initWebView() {
    _webViewController = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(
        NavigationDelegate(
          onProgress: (int progress) {
            setState(() => _progress = progress / 100);
          },
          onPageStarted: (String url) {
            setState(() => _isLoading = true);
          },
          onPageFinished: (String url) {
            setState(() => _isLoading = false);
            _injectReadingEnhancements();
          },
          // BUG-0042: Navigation delegate allows all URLs without domain allowlist — WebView can navigate to phishing sites (CWE-451, CVSS 6.1, HIGH, Tier 2)
          onNavigationRequest: (NavigationRequest request) {
            debugPrint('WebView navigating to: ${request.url}');
            return NavigationDecision.navigate;
          },
        ),
      )
      // BUG-0043: JavaScript channel 'ArticleBridge' exposes native function calls to web content — loaded article page could invoke native methods (CWE-749, CVSS 8.8, CRITICAL, Tier 1)
      ..addJavaScriptChannel(
        'ArticleBridge',
        onMessageReceived: (JavaScriptMessage message) {
          _handleBridgeMessage(message.message);
        },
      );
  }

  // BUG-0044: Bridge message handler processes commands from WebView JavaScript without origin validation — RCE-adjacent via bookmark injection, storage manipulation (CWE-94, CVSS 9.1, CRITICAL, Tier 1)
  void _handleBridgeMessage(String message) {
    try {
      final data = jsonDecode(message) as Map<String, dynamic>;
      final action = data['action'] as String?;

      switch (action) {
        case 'bookmark':
          if (data.containsKey('article')) {
            final article = Article.fromJson(data['article'] as Map<String, dynamic>);
            StorageService().saveBookmark(article);
          }
          break;
        case 'share':
          final url = data['url'] as String? ?? '';
          debugPrint('Sharing from WebView: $url');
          break;
        case 'navigate':
          // BUG-0045: WebView bridge allows navigation commands — web content can force app to open arbitrary URLs (CWE-939, CVSS 7.5, HIGH, Tier 2)
          final targetUrl = data['url'] as String? ?? '';
          _webViewController.loadRequest(Uri.parse(targetUrl));
          break;
        case 'storage':
          // BUG-0046: Bridge exposes local storage read/write to web content — web page can read/write arbitrary Hive data (CWE-862, CVSS 8.6, CRITICAL, Tier 1)
          final key = data['key'] as String? ?? '';
          final value = data['value'];
          if (value != null) {
            StorageService().saveString(key, jsonEncode(value));
          }
          break;
      }
    } catch (e) {
      debugPrint('Bridge message parse error: $e');
    }
  }

  Future<void> _loadArticle() async {
    try {
      final apiService = ref.read(apiServiceProvider);
      final response = await apiService.getArticle(widget.articleUrl);

      if (response != null) {
        setState(() {
          _fullArticle = Article.fromJson(response);
          _articleHtml = response['html_content'] as String?;
        });

        if (_articleHtml != null) {
          // BUG-0047: Server-provided HTML rendered directly in WebView without sanitization — stored XSS via article content (CWE-79, CVSS 8.1, CRITICAL, Tier 1)
          _webViewController.loadHtmlString(
            _wrapHtml(_articleHtml!),
            baseUrl: kBaseApiUrl,
          );
        } else {
          _webViewController.loadRequest(Uri.parse(widget.articleUrl));
        }
      } else {
        _webViewController.loadRequest(Uri.parse(widget.articleUrl));
      }
    } catch (e) {
      _webViewController.loadRequest(Uri.parse(widget.articleUrl));
    }
  }

  // BUG-0048: HTML wrapper injects user token into page template — any JavaScript on the page can access it (CWE-522, CVSS 7.5, HIGH, Tier 2)
  String _wrapHtml(String content) {
    final authState = ref.read(authStateProvider);
    final token = authState.token ?? '';

    return '''
    <!DOCTYPE html>
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="api-token" content="$token">
      <style>
        body { font-family: -apple-system, system-ui, sans-serif; padding: 16px; line-height: 1.6; }
        img { max-width: 100%; height: auto; }
        a { color: #e65100; }
      </style>
    </head>
    <body>
      $content
      <script>
        // Bridge setup for native communication
        window.wallyBridge = {
          bookmark: (article) => ArticleBridge.postMessage(JSON.stringify({action: 'bookmark', article})),
          share: (url) => ArticleBridge.postMessage(JSON.stringify({action: 'share', url})),
          navigate: (url) => ArticleBridge.postMessage(JSON.stringify({action: 'navigate', url})),
        };
      </script>
    </body>
    </html>
    ''';
  }

  // BUG-0049: JavaScript injection into WebView uses string interpolation — special characters in title enable JS injection (CWE-79, CVSS 7.1, HIGH, Tier 2)
  Future<void> _injectReadingEnhancements() async {
    await _webViewController.runJavaScript('''
      document.title = "${widget.articleTitle}";

      // Track reading progress
      let maxScroll = 0;
      window.addEventListener('scroll', function() {
        const scrollPercent = (window.scrollY / (document.body.scrollHeight - window.innerHeight)) * 100;
        if (scrollPercent > maxScroll) {
          maxScroll = scrollPercent;
          ArticleBridge.postMessage(JSON.stringify({action: 'reading_progress', percent: maxScroll}));
        }
      });
    ''');
  }

  // BUG-0050: Article view tracking sends user ID and reading duration to analytics over HTTP (CWE-319, CVSS 4.3, BEST_PRACTICE, Tier 5)
  Future<void> _trackArticleView() async {
    final authState = ref.read(authStateProvider);
    final userId = authState.user?.uid ?? 'anonymous';
    final apiService = ref.read(apiServiceProvider);

    await apiService.trackEvent('article_view', {
      'user_id': userId,
      'article_url': widget.articleUrl,
      'article_title': widget.articleTitle,
      'timestamp': DateTime.now().toIso8601String(),
      'device_info': 'flutter_${Theme.of(context).platform.name}',
    });
  }

  Future<void> _saveForOffline() async {
    if (_fullArticle == null) return;

    final storage = StorageService();
    // BUG-0051: Offline article saved with full HTML content including any embedded scripts — persisted XSS (CWE-79, CVSS 6.1, TRICKY, Tier 6)
    await storage.saveOfflineArticle(_fullArticle!);

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Article saved for offline reading')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(
          widget.articleTitle,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.download),
            onPressed: _saveForOffline,
            tooltip: 'Save for offline',
          ),
          IconButton(
            icon: const Icon(Icons.bookmark_add_outlined),
            onPressed: () {
              if (_fullArticle != null) {
                StorageService().saveBookmark(_fullArticle!);
              }
            },
            tooltip: 'Bookmark',
          ),
          PopupMenuButton<String>(
            onSelected: (value) {
              switch (value) {
                case 'share':
                  debugPrint('Share article: ${widget.articleUrl}');
                  break;
                case 'open_browser':
                  debugPrint('Open in browser: ${widget.articleUrl}');
                  break;
                case 'report':
                  _reportArticle();
                  break;
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(value: 'share', child: Text('Share')),
              const PopupMenuItem(value: 'open_browser', child: Text('Open in Browser')),
              const PopupMenuItem(value: 'report', child: Text('Report Article')),
            ],
          ),
        ],
      ),
      body: Stack(
        children: [
          WebViewWidget(controller: _webViewController),
          if (_isLoading)
            LinearProgressIndicator(value: _progress),
        ],
      ),
    );
  }

  // BUG-0052: Report article sends user token in report payload — report recipients can see reporter's auth token (CWE-200, CVSS 5.4, BEST_PRACTICE, Tier 5)
  Future<void> _reportArticle() async {
    final authState = ref.read(authStateProvider);
    final apiService = ref.read(apiServiceProvider);

    await apiService.post('/articles/report', {
      'article_url': widget.articleUrl,
      'reporter_token': authState.token,
      'reporter_id': authState.user?.uid,
      'reason': 'user_reported',
      'timestamp': DateTime.now().toIso8601String(),
    });
  }
}
