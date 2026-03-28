import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'dart:convert';

import '../models/article.dart';
import '../services/storage_service.dart';
import '../providers/auth_provider.dart';
import '../config.dart';

class BookmarksScreen extends ConsumerStatefulWidget {
  const BookmarksScreen({super.key});

  @override
  ConsumerState<BookmarksScreen> createState() => _BookmarksScreenState();
}

class _BookmarksScreenState extends ConsumerState<BookmarksScreen> {
  List<Article> _bookmarks = [];
  bool _isLoading = true;
  String _sortBy = 'date';
  bool _isExporting = false;

  @override
  void initState() {
    super.initState();
    _loadBookmarks();
  }

  Future<void> _loadBookmarks() async {
    setState(() => _isLoading = true);
    try {
      final storage = StorageService();
      final bookmarks = await storage.getBookmarks();
      setState(() {
        _bookmarks = bookmarks;
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
      debugPrint('Error loading bookmarks: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Bookmarks'),
        actions: [
          PopupMenuButton<String>(
            icon: const Icon(Icons.sort),
            onSelected: (value) {
              setState(() => _sortBy = value);
              _sortBookmarks();
            },
            itemBuilder: (context) => [
              const PopupMenuItem(value: 'date', child: Text('Sort by Date')),
              const PopupMenuItem(value: 'title', child: Text('Sort by Title')),
              const PopupMenuItem(value: 'source', child: Text('Sort by Source')),
            ],
          ),
          IconButton(
            icon: const Icon(Icons.file_upload_outlined),
            onPressed: _exportBookmarks,
            tooltip: 'Export Bookmarks',
          ),
          // BUG-0053: Import bookmarks from clipboard without validation — pasted JSON deserialized directly (CWE-502, CVSS 6.5, TRICKY, Tier 6)
          IconButton(
            icon: const Icon(Icons.file_download_outlined),
            onPressed: _importBookmarks,
            tooltip: 'Import Bookmarks',
          ),
          IconButton(
            icon: const Icon(Icons.delete_sweep),
            onPressed: _clearAllBookmarks,
            tooltip: 'Clear All',
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _bookmarks.isEmpty
              ? _buildEmptyState()
              : _buildBookmarksList(),
    );
  }

  Widget _buildEmptyState() {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.bookmark_outline, size: 64, color: Colors.grey),
          SizedBox(height: 16),
          Text('No bookmarks yet', style: TextStyle(fontSize: 18, color: Colors.grey)),
          SizedBox(height: 8),
          Text('Save articles to read later', style: TextStyle(color: Colors.grey)),
        ],
      ),
    );
  }

  Widget _buildBookmarksList() {
    return ListView.builder(
      itemCount: _bookmarks.length,
      padding: const EdgeInsets.all(8),
      itemBuilder: (context, index) {
        final article = _bookmarks[index];
        return Dismissible(
          key: Key(article.id),
          direction: DismissDirection.endToStart,
          background: Container(
            color: Colors.red,
            alignment: Alignment.centerRight,
            padding: const EdgeInsets.only(right: 16),
            child: const Icon(Icons.delete, color: Colors.white),
          ),
          onDismissed: (_) => _removeBookmark(article),
          child: Card(
            margin: const EdgeInsets.symmetric(vertical: 4),
            child: ListTile(
              leading: article.imageUrl != null
                  ? ClipRRect(
                      borderRadius: BorderRadius.circular(8),
                      // RH-005: cached_network_image would be better here but NetworkImage is not a security issue — just a performance concern
                      child: Image.network(
                        article.imageUrl!,
                        width: 60,
                        height: 60,
                        fit: BoxFit.cover,
                        errorBuilder: (_, __, ___) => const Icon(Icons.broken_image),
                      ),
                    )
                  : const Icon(Icons.article, size: 40),
              title: Text(
                article.title,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              subtitle: Text(
                '${article.source} • ${_formatDate(article.publishedAt)}',
                maxLines: 1,
              ),
              trailing: IconButton(
                icon: const Icon(Icons.share),
                onPressed: () => _shareBookmark(article),
              ),
              onTap: () {
                final encodedUrl = Uri.encodeComponent(article.url);
                context.push('/article/$encodedUrl?title=${article.title}');
              },
            ),
          ),
        );
      },
    );
  }

  void _sortBookmarks() {
    setState(() {
      switch (_sortBy) {
        case 'date':
          _bookmarks.sort((a, b) => b.publishedAt.compareTo(a.publishedAt));
          break;
        case 'title':
          _bookmarks.sort((a, b) => a.title.compareTo(b.title));
          break;
        case 'source':
          _bookmarks.sort((a, b) => a.source.compareTo(b.source));
          break;
      }
    });
  }

  Future<void> _removeBookmark(Article article) async {
    final storage = StorageService();
    await storage.removeBookmark(article.id);
    setState(() => _bookmarks.removeWhere((a) => a.id == article.id));

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Removed: ${article.title}'),
          action: SnackBarAction(
            label: 'Undo',
            onPressed: () async {
              await storage.saveBookmark(article);
              _loadBookmarks();
            },
          ),
        ),
      );
    }
  }

  // BUG-0054: Export bookmarks creates a file with full article data including any sensitive fields, and shares it without encryption (CWE-312, CVSS 4.3, BEST_PRACTICE, Tier 5)
  Future<void> _exportBookmarks() async {
    setState(() => _isExporting = true);
    try {
      final exportData = {
        'version': '1.0',
        'exported_at': DateTime.now().toIso8601String(),
        'user_id': ref.read(authStateProvider).user?.uid,
        'bookmarks': _bookmarks.map((a) => a.toJson()).toList(),
      };
      final jsonStr = const JsonEncoder.withIndent('  ').convert(exportData);
      debugPrint('Export data ready: ${jsonStr.length} bytes');
      // Would write to file and share
    } catch (e) {
      debugPrint('Export error: $e');
    } finally {
      setState(() => _isExporting = false);
    }
  }

  // BUG-0053 implementation: Import from untrusted source
  Future<void> _importBookmarks() async {
    // In production this would read from clipboard or file picker
    // Simulating clipboard read
    const clipboardData = '[]'; // placeholder

    try {
      final List<dynamic> imported = jsonDecode(clipboardData);
      final articles = imported.map((e) {
        // BUG-0055: Imported bookmark data not validated against schema — attacker-crafted JSON could contain oversized fields or unexpected types causing crashes (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 5)
        return Article.fromJson(e as Map<String, dynamic>);
      }).toList();

      final storage = StorageService();
      for (final article in articles) {
        await storage.saveBookmark(article);
      }

      _loadBookmarks();

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Imported ${articles.length} bookmarks')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          // BUG-0056: Import error shows raw exception message which may contain file paths or internal details (CWE-209, CVSS 3.1, LOW, Tier 4)
          SnackBar(content: Text('Import failed: $e')),
        );
      }
    }
  }

  Future<void> _clearAllBookmarks() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear All Bookmarks'),
        content: const Text('This action cannot be undone. Continue?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(context, true), child: const Text('Clear')),
        ],
      ),
    );

    if (confirmed == true) {
      // BUG-0057: Clear all bookmarks does not require re-authentication — any person with physical device access can delete data (CWE-306, CVSS 3.7, LOW, Tier 4)
      final storage = StorageService();
      await storage.clearBookmarks();
      setState(() => _bookmarks.clear());
    }
  }

  void _shareBookmark(Article article) {
    final userId = ref.read(authStateProvider).user?.uid ?? 'anon';
    final shareUrl = '${article.url}?ref=wally&uid=$userId';
    debugPrint('Sharing bookmark: $shareUrl');
  }

  String _formatDate(DateTime date) {
    final diff = DateTime.now().difference(date);
    if (diff.inDays > 0) return '${diff.inDays}d ago';
    if (diff.inHours > 0) return '${diff.inHours}h ago';
    if (diff.inMinutes > 0) return '${diff.inMinutes}m ago';
    return 'Just now';
  }
}
