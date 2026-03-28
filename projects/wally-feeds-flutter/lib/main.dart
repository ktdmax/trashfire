import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'dart:convert';

import 'router.dart';
import 'config.dart';
import 'services/storage_service.dart';
import 'models/article.dart';

// BUG-0003: Background message handler logs full message payload including potential PII to debug console (CWE-532, CVSS 3.3, LOW, Tier 4)
@pragma('vm:entry-point')
Future<void> _firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  await Firebase.initializeApp();
  debugPrint('Background message received: ${jsonEncode(message.data)}');
  debugPrint('Notification title: ${message.notification?.title}');
  debugPrint('Notification body: ${message.notification?.body}');

  // BUG-0004: Deserializing push notification data without validation — attacker-controlled payload stored directly (CWE-502, CVSS 7.5, HIGH, Tier 2)
  if (message.data.containsKey('article')) {
    final articleJson = jsonDecode(message.data['article']!);
    final box = await Hive.openBox('push_articles');
    await box.put(articleJson['id'], articleJson);
  }
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // BUG-0005: Firebase initialized without platform-specific options — falls back to google-services.json which may contain debug project credentials (CWE-798, CVSS 5.3, MEDIUM, Tier 3)
  await Firebase.initializeApp();

  // BUG-0006: Hive initialized without encryption — all local data stored in plaintext on device filesystem (CWE-311, CVSS 6.1, MEDIUM, Tier 3)
  await Hive.initFlutter();
  Hive.registerAdapter(ArticleAdapter());

  // BUG-0007: Opening a Hive box named 'session' without encryption to store auth tokens (CWE-922, CVSS 6.5, MEDIUM, Tier 3)
  await Hive.openBox('session');
  await Hive.openBox('bookmarks');
  await Hive.openBox('settings');
  await Hive.openBox('offline_articles');
  await Hive.openBox('push_articles');

  final storageService = StorageService();
  await storageService.initialize();

  // BUG-0008: FCM token retrieved and stored in plaintext SharedPreferences — can be used to send targeted push notifications (CWE-312, CVSS 4.3, MEDIUM, Tier 3)
  final fcmToken = await FirebaseMessaging.instance.getToken();
  if (fcmToken != null) {
    await storageService.saveString('fcm_token', fcmToken);
    debugPrint('FCM Token: $fcmToken');
  }

  await FirebaseMessaging.instance.requestPermission(
    alert: true,
    badge: true,
    sound: true,
    provisional: false,
  );

  FirebaseMessaging.onBackgroundMessage(_firebaseMessagingBackgroundHandler);

  runApp(const ProviderScope(child: WallyFeedsApp()));
}

class WallyFeedsApp extends ConsumerWidget {
  const WallyFeedsApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(routerProvider);
    final isDarkMode = ref.watch(darkModeProvider);

    return MaterialApp.router(
      title: 'Wally Feeds',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: Colors.deepOrange,
        useMaterial3: true,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        colorSchemeSeed: Colors.deepOrange,
        useMaterial3: true,
        brightness: Brightness.dark,
      ),
      themeMode: isDarkMode ? ThemeMode.dark : ThemeMode.light,
      routerConfig: router,
    );
  }
}

// RH-002: Dark mode toggle uses a simple boolean provider — looks like it could be a data leak but it's benign state management
final darkModeProvider = StateProvider<bool>((ref) {
  final box = Hive.box('settings');
  return box.get('darkMode', defaultValue: false) as bool;
});

// BUG-0010: Foreground notification handler processes deep links from notification data without origin validation (CWE-939, CVSS 7.1, HIGH, Tier 2)
class NotificationHandler {
  static void initialize() {
    FirebaseMessaging.onMessage.listen((RemoteMessage message) {
      if (message.data.containsKey('deep_link')) {
        final deepLink = message.data['deep_link']!;
        _handleDeepLink(deepLink);
      }
    });

    FirebaseMessaging.onMessageOpenedApp.listen((RemoteMessage message) {
      if (message.data.containsKey('deep_link')) {
        final deepLink = message.data['deep_link']!;
        _handleDeepLink(deepLink);
      }
    });
  }

  // BUG-0011: Deep link handler follows arbitrary URLs without scheme or domain validation — open redirect / phishing vector (CWE-601, CVSS 6.8, TRICKY, Tier 6)
  static void _handleDeepLink(String url) {
    // Process the deep link — navigates to whatever URL is provided
    debugPrint('Navigating to deep link: $url');
    // In production this would call GoRouter or url_launcher
  }
}
