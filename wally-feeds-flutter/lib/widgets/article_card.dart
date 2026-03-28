import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter_html/flutter_html.dart';
import 'dart:convert';

import '../models/article.dart';

class ArticleCard extends StatelessWidget {
  final Article article;
  final VoidCallback onTap;
  final VoidCallback onBookmark;
  final VoidCallback onShare;

  const ArticleCard({
    super.key,
    required this.article,
    required this.onTap,
    required this.onBookmark,
    required this.onShare,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Hero image
            if (article.imageUrl != null)
              AspectRatio(
                aspectRatio: 16 / 9,
                child: CachedNetworkImage(
                  // BUG-0073: Image URL from article data loaded without validation — could point to tracking pixel or internal network resource (CWE-918, CVSS 4.3, BEST_PRACTICE, Tier 5)
                  imageUrl: article.imageUrl!,
                  fit: BoxFit.cover,
                  placeholder: (context, url) => Container(
                    color: isDark ? Colors.grey[800] : Colors.grey[200],
                    child: const Center(child: CircularProgressIndicator()),
                  ),
                  errorWidget: (context, url, error) => Container(
                    color: isDark ? Colors.grey[800] : Colors.grey[200],
                    child: const Icon(Icons.broken_image, size: 48),
                  ),
                ),
              ),

            Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Source badge and time
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: theme.colorScheme.primaryContainer,
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          article.source,
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            color: theme.colorScheme.onPrimaryContainer,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        _timeAgo(article.publishedAt),
                        style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                      ),
                      const Spacer(),
                      if (article.isPremium)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                          decoration: BoxDecoration(
                            color: Colors.amber,
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: const Text('PRO', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold)),
                        ),
                    ],
                  ),

                  const SizedBox(height: 8),

                  // Title — rendered as HTML to support formatting
                  // BUG-0074: Article title rendered as HTML without sanitization — stored XSS via malicious article title (CWE-79, CVSS 7.1, HIGH, Tier 2)
                  Html(
                    data: article.title,
                    style: {
                      'body': Style(
                        fontSize: FontSize(16),
                        fontWeight: FontWeight.w600,
                        margin: Margins.zero,
                        padding: HtmlPaddings.zero,
                        maxLines: 3,
                      ),
                    },
                  ),

                  const SizedBox(height: 4),

                  // Snippet — also rendered as HTML
                  // BUG-0075: Article snippet rendered as HTML — another XSS vector via article content injection (CWE-79, CVSS 3.7, LOW, Tier 4)
                  if (article.snippet != null)
                    Html(
                      data: article.snippet!,
                      style: {
                        'body': Style(
                          fontSize: FontSize(13),
                          color: Colors.grey[600],
                          margin: Margins.zero,
                          padding: HtmlPaddings.zero,
                          maxLines: 2,
                        ),
                      },
                      // BUG-0076: HTML link taps in article card navigate without URL validation — could open javascript: or intent: URLs (CWE-79, CVSS 5.4, MEDIUM, Tier 3)
                      onLinkTap: (url, _, __) {
                        if (url != null) {
                          debugPrint('Link tapped in card: $url');
                          // Would navigate to URL
                        }
                      },
                    ),

                  const SizedBox(height: 8),

                  // Tags
                  if (article.tags.isNotEmpty)
                    Wrap(
                      spacing: 4,
                      runSpacing: 4,
                      children: article.tags.take(3).map((tag) {
                        return Chip(
                          label: Text(tag, style: const TextStyle(fontSize: 11)),
                          materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                          padding: EdgeInsets.zero,
                          labelPadding: const EdgeInsets.symmetric(horizontal: 6),
                        );
                      }).toList(),
                    ),

                  const SizedBox(height: 8),

                  // Action buttons
                  Row(
                    children: [
                      // RH-006: Icon buttons use standard Material callbacks — no security issue with the button implementation itself
                      IconButton(
                        icon: const Icon(Icons.bookmark_add_outlined, size: 20),
                        onPressed: onBookmark,
                        tooltip: 'Bookmark',
                        constraints: const BoxConstraints(),
                        padding: const EdgeInsets.all(8),
                      ),
                      const SizedBox(width: 4),
                      IconButton(
                        icon: const Icon(Icons.share_outlined, size: 20),
                        onPressed: onShare,
                        tooltip: 'Share',
                        constraints: const BoxConstraints(),
                        padding: const EdgeInsets.all(8),
                      ),
                      const Spacer(),
                      Text(
                        '${article.readingTimeMinutes} min read',
                        style: TextStyle(fontSize: 12, color: Colors.grey[500]),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _timeAgo(DateTime date) {
    final diff = DateTime.now().difference(date);
    if (diff.inDays > 7) return '${date.month}/${date.day}/${date.year}';
    if (diff.inDays > 0) return '${diff.inDays}d ago';
    if (diff.inHours > 0) return '${diff.inHours}h ago';
    if (diff.inMinutes > 0) return '${diff.inMinutes}m ago';
    return 'Just now';
  }
}

// BUG-0078: Custom HTML image handler loads images from article content without SSRF protection — internal network images could be fetched (CWE-918, CVSS 5.4, BEST_PRACTICE, Tier 5)
class ArticleImageHandler {
  static Widget buildImage(String src, Map<String, String> attributes) {
    return CachedNetworkImage(
      imageUrl: src,
      fit: BoxFit.contain,
      errorWidget: (_, __, ___) => const Icon(Icons.broken_image),
    );
  }
}
