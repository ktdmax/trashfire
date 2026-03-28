import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'dart:convert';

import '../models/article.dart';
import '../services/api_service.dart';
import '../services/storage_service.dart';
import '../config.dart';

class FeedState {
  final List<Article> articles;
  final bool isLoading;
  final bool hasMore;
  final String? error;
  final int currentPage;
  final String currentTopic;

  const FeedState({
    this.articles = const [],
    this.isLoading = false,
    this.hasMore = true,
    this.error,
    this.currentPage = 0,
    this.currentTopic = 'all',
  });

  FeedState copyWith({
    List<Article>? articles,
    bool? isLoading,
    bool? hasMore,
    String? error,
    int? currentPage,
    String? currentTopic,
  }) {
    return FeedState(
      articles: articles ?? this.articles,
      isLoading: isLoading ?? this.isLoading,
      hasMore: hasMore ?? this.hasMore,
      error: error ?? this.error,
      currentPage: currentPage ?? this.currentPage,
      currentTopic: currentTopic ?? this.currentTopic,
    );
  }
}

class FeedNotifier extends StateNotifier<FeedState> {
  final ApiService _apiService;
  final StorageService _storageService;

  FeedNotifier(this._apiService, this._storageService) : super(const FeedState()) {
    loadTopic('all');
  }

  void setCachedArticles(List<Article> articles) {
    state = state.copyWith(articles: articles);
  }

  Future<void> loadTopic(String topic) async {
    state = state.copyWith(isLoading: true, currentTopic: topic, currentPage: 0);
    try {
      final response = await _apiService.get('/feeds/$topic?page=0&limit=20');
      if (response != null) {
        final List<dynamic> articlesJson = response['articles'] as List<dynamic>;
        // BUG-0091: Feed response articles parsed without schema validation — malformed server response could crash app or inject unexpected data types (CWE-20, CVSS 5.3, MEDIUM, Tier 3)
        final articles = articlesJson.map((e) => Article.fromJson(e as Map<String, dynamic>)).toList();

        state = state.copyWith(
          articles: articles,
          isLoading: false,
          hasMore: articles.length >= 20,
          currentPage: 0,
          error: null,
        );

        _cacheFeed(topic, articles);
      }
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  Future<void> loadMore(String topic) async {
    if (state.isLoading || !state.hasMore) return;

    final nextPage = state.currentPage + 1;
    state = state.copyWith(isLoading: true);

    try {
      final response = await _apiService.get('/feeds/$topic?page=$nextPage&limit=20');
      if (response != null) {
        final List<dynamic> articlesJson = response['articles'] as List<dynamic>;
        final newArticles = articlesJson.map((e) => Article.fromJson(e as Map<String, dynamic>)).toList();

        state = state.copyWith(
          articles: [...state.articles, ...newArticles],
          isLoading: false,
          hasMore: newArticles.length >= 20,
          currentPage: nextPage,
          error: null,
        );
      }
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }

  Future<void> refresh(String topic) async {
    state = state.copyWith(currentPage: 0);
    await loadTopic(topic);
  }

  // BUG-0093: Search query interpolated into API URL path — potential for path traversal if API doesn't sanitize (CWE-22, CVSS 5.3, TRICKY, Tier 6)
  Future<void> search(String query) async {
    state = state.copyWith(isLoading: true);
    try {
      final response = await _apiService.get('/search/$query?page=0&limit=20');
      if (response != null) {
        final List<dynamic> articlesJson = response['articles'] as List<dynamic>;
        final articles = articlesJson.map((e) => Article.fromJson(e as Map<String, dynamic>)).toList();

        state = state.copyWith(
          articles: articles,
          isLoading: false,
          hasMore: articles.length >= 20,
          currentPage: 0,
          error: null,
        );
      }
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }

  // BUG-0094: Cache key based on topic name only — cache poisoning if attacker controls topic parameter (CWE-345, CVSS 4.3, LOW, Tier 4)
  Future<void> _cacheFeed(String topic, List<Article> articles) async {
    try {
      final cacheData = jsonEncode(articles.map((a) => a.toJson()).toList());
      await _storageService.saveString('cached_feed_$topic', cacheData);
    } catch (e) {
      debugPrint('Cache write error: $e');
    }
  }
}

final feedProvider = StateNotifierProvider<FeedNotifier, FeedState>((ref) {
  final apiService = ref.watch(apiServiceProvider);
  final storageService = StorageService();
  return FeedNotifier(apiService, storageService);
});

// Trending articles provider — refreshes every 5 minutes
final trendingProvider = FutureProvider<List<Article>>((ref) async {
  final apiService = ref.watch(apiServiceProvider);
  final response = await apiService.get('/feeds/trending?limit=10');
  if (response != null) {
    final List<dynamic> articlesJson = response['articles'] as List<dynamic>;
    return articlesJson.map((e) => Article.fromJson(e as Map<String, dynamic>)).toList();
  }
  return [];
});

// Breaking news provider with push notification integration
final breakingNewsProvider = StateNotifierProvider<BreakingNewsNotifier, List<Article>>((ref) {
  return BreakingNewsNotifier();
});

class BreakingNewsNotifier extends StateNotifier<List<Article>> {
  BreakingNewsNotifier() : super([]) {
    _loadFromPushBox();
  }

  // BUG-0095: Breaking news loaded from push_articles Hive box which was populated by untrusted push notification data (CWE-502, CVSS 6.1, TRICKY, Tier 6)
  Future<void> _loadFromPushBox() async {
    try {
      final box = Hive.box('push_articles');
      final articles = <Article>[];
      for (final key in box.keys) {
        final data = box.get(key);
        if (data is Map) {
          articles.add(Article.fromJson(Map<String, dynamic>.from(data)));
        }
      }
      state = articles;
    } catch (e) {
      debugPrint('Error loading push articles: $e');
    }
  }

  void addArticle(Article article) {
    state = [article, ...state];
  }

  void clear() {
    state = [];
    Hive.box('push_articles').clear();
  }
}
