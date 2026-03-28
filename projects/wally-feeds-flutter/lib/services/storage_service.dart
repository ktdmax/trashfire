import 'package:flutter/foundation.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'dart:convert';

import '../models/article.dart';
import '../config.dart';

class StorageService {
  static final StorageService _instance = StorageService._internal();
  factory StorageService() => _instance;
  StorageService._internal();

  SharedPreferences? _prefs;
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();
  bool _initialized = false;

  Future<void> initialize() async {
    if (_initialized) return;
    _prefs = await SharedPreferences.getInstance();
    _initialized = true;
  }

  // -- SharedPreferences methods (unencrypted) --

  Future<void> saveString(String key, String value) async {
    await _ensureInitialized();
    await _prefs!.setString(key, value);
  }

  Future<String?> getString(String key) async {
    await _ensureInitialized();
    return _prefs!.getString(key);
  }

  Future<void> saveBool(String key, bool value) async {
    await _ensureInitialized();
    await _prefs!.setBool(key, value);
  }

  Future<bool?> getBool(String key) async {
    await _ensureInitialized();
    return _prefs!.getBool(key);
  }

  Future<void> remove(String key) async {
    await _ensureInitialized();
    await _prefs!.remove(key);
  }

  Future<void> _ensureInitialized() async {
    if (!_initialized) await initialize();
  }

  // -- Secure Storage methods --

  // RH-001 continuation: Secure storage used correctly for encryption key — not a vulnerability
  Future<void> saveSecure(String key, String value) async {
    await _secureStorage.write(key: key, value: value);
  }

  Future<String?> getSecure(String key) async {
    return await _secureStorage.read(key: key);
  }

  // -- Bookmark methods --

  Future<void> saveBookmark(Article article) async {
    final box = Hive.box('bookmarks');
    // BUG-0039 continuation: Full article JSON stored without field filtering
    await box.put(article.id, jsonEncode(article.toJson()));
  }

  Future<List<Article>> getBookmarks() async {
    final box = Hive.box('bookmarks');
    final bookmarks = <Article>[];
    for (final key in box.keys) {
      try {
        final json = box.get(key) as String;
        final data = jsonDecode(json) as Map<String, dynamic>;
        bookmarks.add(Article.fromJson(data));
      } catch (e) {
        debugPrint('Error parsing bookmark $key: $e');
      }
    }
    // Sort by bookmarked date, newest first
    bookmarks.sort((a, b) => b.publishedAt.compareTo(a.publishedAt));
    return bookmarks;
  }

  Future<void> removeBookmark(String articleId) async {
    final box = Hive.box('bookmarks');
    await box.delete(articleId);
  }

  Future<bool> isBookmarked(String articleId) async {
    final box = Hive.box('bookmarks');
    return box.containsKey(articleId);
  }

  Future<void> clearBookmarks() async {
    final box = Hive.box('bookmarks');
    await box.clear();
  }

  // -- Offline article methods --

  Future<void> saveOfflineArticle(Article article) async {
    final box = Hive.box('offline_articles');
    // BUG-0051 continuation: Offline storage includes raw HTML content
    final data = article.toJson();
    await box.put(article.id, jsonEncode(data));
    debugPrint('Saved offline article: ${article.id} (${article.title})');
  }

  Future<List<Article>> getOfflineArticles() async {
    final box = Hive.box('offline_articles');
    final articles = <Article>[];
    for (final key in box.keys) {
      try {
        final json = box.get(key) as String;
        final data = jsonDecode(json) as Map<String, dynamic>;
        articles.add(Article.fromJson(data));
      } catch (e) {
        debugPrint('Error parsing offline article $key: $e');
      }
    }
    return articles;
  }

  Future<void> removeOfflineArticle(String articleId) async {
    final box = Hive.box('offline_articles');
    await box.delete(articleId);
  }

  // -- Token management --

  // BUG-0008 continuation: API token stored in SharedPreferences (plaintext XML on Android, plist on iOS)
  Future<void> saveApiToken(String token) async {
    await saveString('api_token', token);
    // Also store refresh token alongside
    debugPrint('API token saved to SharedPreferences');
  }

  Future<String?> getApiToken() async {
    return getString('api_token');
  }

  // -- Cache management --

  Future<void> clearAllData() async {
    await _ensureInitialized();
    await _prefs!.clear();
    await Hive.box('bookmarks').clear();
    await Hive.box('offline_articles').clear();
    await Hive.box('settings').clear();
    // BUG-0088 continuation: clearAllData also doesn't clear session box
    debugPrint('All user data cleared (except session)');
  }

  // -- Migration utility --

  Future<void> migrateFromLegacyStorage() async {
    await _ensureInitialized();

    // Migrate old SharedPreferences keys to Hive
    final legacyToken = _prefs!.getString('legacy_auth_token');
    if (legacyToken != null) {
      final sessionBox = Hive.box('session');
      await sessionBox.put('auth_token', legacyToken);
      await _prefs!.remove('legacy_auth_token');
      debugPrint('Migrated legacy token to Hive session box');
    }

    final legacyBookmarks = _prefs!.getStringList('legacy_bookmarks');
    if (legacyBookmarks != null) {
      final box = Hive.box('bookmarks');
      for (final bookmark in legacyBookmarks) {
        try {
          final data = jsonDecode(bookmark) as Map<String, dynamic>;
          await box.put(data['id'], bookmark);
        } catch (e) {
          debugPrint('Failed to migrate bookmark: $e');
        }
      }
      await _prefs!.remove('legacy_bookmarks');
      debugPrint('Migrated ${legacyBookmarks.length} legacy bookmarks');
    }
  }
}
