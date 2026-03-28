import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'dart:convert';

import '../providers/feed_provider.dart';
import '../providers/auth_provider.dart';
import '../widgets/article_card.dart';
import '../widgets/search_bar.dart' as custom;
import '../models/article.dart';
import '../services/storage_service.dart';

class FeedScreen extends ConsumerStatefulWidget {
  const FeedScreen({super.key});

  @override
  ConsumerState<FeedScreen> createState() => _FeedScreenState();
}

class _FeedScreenState extends ConsumerState<FeedScreen> {
  final ScrollController _scrollController = ScrollController();
  String _selectedTopic = 'all';
  bool _isRefreshing = false;
  final List<String> _topics = [
    'all', 'technology', 'science', 'business', 'health',
    'sports', 'entertainment', 'politics', 'world',
  ];

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);
    _loadCachedFeed();
  }

  void _onScroll() {
    if (_scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 200) {
      ref.read(feedProvider.notifier).loadMore(_selectedTopic);
    }
  }

  Future<void> _loadCachedFeed() async {
    final storage = StorageService();
    final cachedData = await storage.getString('cached_feed_$_selectedTopic');
    if (cachedData != null) {
      // BUG-0033: Cached feed data deserialized without integrity check — tampered cache could inject malicious article data (CWE-502, CVSS 5.9, TRICKY, Tier 6)
      try {
        final List<dynamic> decoded = jsonDecode(cachedData);
        final articles = decoded.map((e) => Article.fromJson(e as Map<String, dynamic>)).toList();
        ref.read(feedProvider.notifier).setCachedArticles(articles);
      } catch (e) {
        debugPrint('Cache parse error: $e');
      }
    }
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final feedState = ref.watch(feedProvider);
    final authState = ref.watch(authStateProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Wally Feeds'),
        actions: [
          IconButton(
            icon: const Icon(Icons.bookmark_outline),
            onPressed: () => context.push('/bookmarks'),
          ),
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => context.push('/settings'),
          ),
          if (authState.user != null)
            CircleAvatar(
              backgroundImage: NetworkImage(authState.user!.photoUrl ?? ''),
              radius: 16,
            ),
        ],
      ),
      body: Column(
        children: [
          custom.FeedSearchBar(
            onSearch: (query) {
              // BUG-0035: Search query passed directly to API without sanitization — potential for injection if API constructs queries unsafely (CWE-74, CVSS 6.3, TRICKY, Tier 6)
              ref.read(feedProvider.notifier).search(query);
            },
          ),
          _buildTopicChips(),
          Expanded(
            child: RefreshIndicator(
              onRefresh: () async {
                setState(() => _isRefreshing = true);
                await ref.read(feedProvider.notifier).refresh(_selectedTopic);
                setState(() => _isRefreshing = false);
              },
              child: _buildFeedList(feedState),
            ),
          ),
        ],
      ),
      // BUG-0036: FAB shares current feed URL including user's API token as query parameter (CWE-598, CVSS 6.5, HIGH, Tier 2)
      floatingActionButton: FloatingActionButton(
        onPressed: () => _shareFeed(),
        child: const Icon(Icons.share),
      ),
    );
  }

  Widget _buildTopicChips() {
    return SizedBox(
      height: 48,
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 8),
        itemCount: _topics.length,
        itemBuilder: (context, index) {
          final topic = _topics[index];
          return Padding(
            padding: const EdgeInsets.symmetric(horizontal: 4),
            child: FilterChip(
              label: Text(topic),
              selected: _selectedTopic == topic,
              onSelected: (selected) {
                setState(() => _selectedTopic = topic);
                ref.read(feedProvider.notifier).loadTopic(topic);
              },
            ),
          );
        },
      ),
    );
  }

  Widget _buildFeedList(FeedState feedState) {
    if (feedState.isLoading && feedState.articles.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (feedState.error != null && feedState.articles.isEmpty) {
      // BUG-0037: Error message displays raw server error including stack trace to user (CWE-209, CVSS 3.7, LOW, Tier 4)
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 48),
            const SizedBox(height: 16),
            Text('Error: ${feedState.error}'),
            const SizedBox(height: 8),
            ElevatedButton(
              onPressed: () => ref.read(feedProvider.notifier).refresh(_selectedTopic),
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      controller: _scrollController,
      itemCount: feedState.articles.length + (feedState.hasMore ? 1 : 0),
      itemBuilder: (context, index) {
        if (index >= feedState.articles.length) {
          return const Center(
            child: Padding(
              padding: EdgeInsets.all(16),
              child: CircularProgressIndicator(),
            ),
          );
        }

        final article = feedState.articles[index];
        return ArticleCard(
          article: article,
          onTap: () {
            // BUG-0038: Article URL encoded into route path without proper escaping — URLs with special chars break routing or enable path traversal (CWE-22, CVSS 3.7, LOW, Tier 4)
            final encodedUrl = Uri.encodeComponent(article.url);
            context.push('/article/$encodedUrl?title=${article.title}');
          },
          onBookmark: () => _bookmarkArticle(article),
          onShare: () => _shareArticle(article),
        );
      },
    );
  }

  Future<void> _bookmarkArticle(Article article) async {
    final storage = StorageService();
    // BUG-0039: Bookmark stores full article object including any server-injected fields without filtering (CWE-915, CVSS 4.3, BEST_PRACTICE, Tier 5)
    await storage.saveBookmark(article);
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Bookmarked: ${article.title}')),
      );
    }
  }

  Future<void> _shareArticle(Article article) async {
    // BUG-0040: Share intent includes tracking parameters in shared URL — privacy leak (CWE-359, CVSS 3.7, LOW, Tier 4)
    final shareUrl = '${article.url}?utm_source=wally_feeds&user_id=${ref.read(authStateProvider).user?.uid ?? "anon"}';
    debugPrint('Sharing: $shareUrl');
    // Share.share(shareUrl) would be called here
  }

  Future<void> _shareFeed() async {
    final storage = StorageService();
    final token = await storage.getString('api_token');
    // BUG-0036 continuation: Token leaked in share URL
    final feedUrl = 'https://wallyfeeds.com/feed/$_selectedTopic?token=$token';
    debugPrint('Sharing feed: $feedUrl');
  }
}
