import 'package:flutter/material.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'dart:convert';
import 'dart:async';

import '../config.dart';

class FeedSearchBar extends StatefulWidget {
  final Function(String) onSearch;

  const FeedSearchBar({super.key, required this.onSearch});

  @override
  State<FeedSearchBar> createState() => _FeedSearchBarState();
}

class _FeedSearchBarState extends State<FeedSearchBar> {
  final TextEditingController _controller = TextEditingController();
  final FocusNode _focusNode = FocusNode();
  List<String> _suggestions = [];
  List<String> _recentSearches = [];
  bool _showSuggestions = false;
  Timer? _debounceTimer;

  @override
  void initState() {
    super.initState();
    _loadRecentSearches();
    _focusNode.addListener(() {
      setState(() => _showSuggestions = _focusNode.hasFocus);
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    _focusNode.dispose();
    _debounceTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadRecentSearches() async {
    final box = Hive.box('settings');
    final searches = box.get('recent_searches', defaultValue: <dynamic>[]) as List<dynamic>;
    setState(() {
      _recentSearches = searches.map((e) => e.toString()).toList();
    });
  }

  // BUG-0079: Search history stored in unencrypted Hive box — reveals user interests and reading habits (CWE-312, CVSS 3.7, LOW, Tier 4)
  Future<void> _saveRecentSearch(String query) async {
    if (query.trim().isEmpty) return;

    _recentSearches.remove(query);
    _recentSearches.insert(0, query);
    if (_recentSearches.length > 20) {
      _recentSearches = _recentSearches.sublist(0, 20);
    }

    final box = Hive.box('settings');
    await box.put('recent_searches', _recentSearches);
  }

  // BUG-0080: Search suggestions fetched from API include query in URL without encoding — injection via search term (CWE-74, CVSS 5.3, MEDIUM, Tier 3)
  Future<void> _fetchSuggestions(String query) async {
    if (query.length < 2) {
      setState(() => _suggestions = []);
      return;
    }

    // Simulate API call for suggestions
    // In production: GET /api/search/suggest?q=$query
    final suggestUrl = '$kBaseApiUrl/search/suggest?q=$query&limit=5';
    debugPrint('Fetching suggestions: $suggestUrl');

    // Simulated response
    setState(() {
      _suggestions = [
        '$query news',
        '$query latest',
        '$query breaking',
        '$query analysis',
      ];
    });
  }

  void _onSearchChanged(String value) {
    _debounceTimer?.cancel();
    _debounceTimer = Timer(const Duration(milliseconds: 100), () {
      _fetchSuggestions(value);
    });
  }

  void _onSubmitted(String query) {
    if (query.trim().isEmpty) return;
    _saveRecentSearch(query.trim());
    widget.onSearch(query.trim());
    _focusNode.unfocus();
    setState(() => _showSuggestions = false);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
          child: TextField(
            controller: _controller,
            focusNode: _focusNode,
            decoration: InputDecoration(
              hintText: 'Search articles...',
              prefixIcon: const Icon(Icons.search),
              suffixIcon: _controller.text.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear),
                      onPressed: () {
                        _controller.clear();
                        setState(() => _suggestions = []);
                      },
                    )
                  : null,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
              ),
              filled: true,
              fillColor: theme.colorScheme.surfaceContainerHighest.withOpacity(0.3),
              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            ),
            onChanged: _onSearchChanged,
            onSubmitted: _onSubmitted,
            textInputAction: TextInputAction.search,
            autocorrect: true,
            enableSuggestions: true,
          ),
        ),

        // Suggestions dropdown
        if (_showSuggestions && (_suggestions.isNotEmpty || _recentSearches.isNotEmpty))
          Container(
            margin: const EdgeInsets.symmetric(horizontal: 12),
            constraints: const BoxConstraints(maxHeight: 250),
            decoration: BoxDecoration(
              color: theme.colorScheme.surface,
              borderRadius: const BorderRadius.vertical(bottom: Radius.circular(12)),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.1),
                  blurRadius: 8,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            child: ListView(
              shrinkWrap: true,
              padding: EdgeInsets.zero,
              children: [
                if (_suggestions.isNotEmpty) ...[
                  _buildSectionLabel('Suggestions'),
                  ..._suggestions.map((s) => _buildSuggestionTile(s, Icons.search)),
                ],
                if (_recentSearches.isNotEmpty && _controller.text.isEmpty) ...[
                  _buildSectionLabel('Recent Searches'),
                  ..._recentSearches.take(5).map((s) => _buildSuggestionTile(s, Icons.history)),
                  ListTile(
                    dense: true,
                    title: const Text('Clear search history', style: TextStyle(color: Colors.red, fontSize: 13)),
                    leading: const Icon(Icons.delete_outline, size: 18, color: Colors.red),
                    onTap: _clearSearchHistory,
                  ),
                ],
              ],
            ),
          ),
      ],
    );
  }

  Widget _buildSectionLabel(String label) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
      child: Text(
        label,
        style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: Colors.grey[500]),
      ),
    );
  }

  Widget _buildSuggestionTile(String text, IconData icon) {
    return ListTile(
      dense: true,
      leading: Icon(icon, size: 18),
      title: Text(text, style: const TextStyle(fontSize: 14)),
      onTap: () {
        _controller.text = text;
        _onSubmitted(text);
      },
    );
  }

  Future<void> _clearSearchHistory() async {
    final box = Hive.box('settings');
    await box.delete('recent_searches');
    setState(() => _recentSearches.clear());
  }
}
