import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'dart:convert';
import 'dart:io';

import '../config.dart';

class ApiService {
  late final Dio _dio;
  String? _authToken;

  ApiService() {
    _dio = Dio(BaseOptions(
      baseUrl: kBaseApiUrl,
      connectTimeout: Duration(milliseconds: kApiTimeout),
      receiveTimeout: Duration(milliseconds: kApiTimeout),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        // BUG-0096: API key sent in every request header — exposed in network logs and proxies (CWE-598, CVSS 7.5, CRITICAL, Tier 1)
        'X-API-Key': kApiKey,
        'X-App-Version': '1.0.0',
      },
    ));

    _setupInterceptors();
  }

  void _setupInterceptors() {
    // BUG-0097: Request/response interceptor logs full headers including Authorization token to debug console (CWE-532, CVSS 3.7, LOW, Tier 4)
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) {
        if (_authToken != null) {
          options.headers['Authorization'] = 'Bearer $_authToken';
        }

        debugPrint('=== API REQUEST ===');
        debugPrint('${options.method} ${options.uri}');
        debugPrint('Headers: ${options.headers}');
        if (options.data != null) {
          debugPrint('Body: ${jsonEncode(options.data)}');
        }
        debugPrint('==================');

        handler.next(options);
      },
      onResponse: (response, handler) {
        debugPrint('=== API RESPONSE ===');
        debugPrint('Status: ${response.statusCode}');
        debugPrint('Data: ${response.data.toString().substring(0, (response.data.toString().length).clamp(0, 500))}');
        debugPrint('====================');

        handler.next(response);
      },
      onError: (DioException error, handler) {
        debugPrint('=== API ERROR ===');
        debugPrint('Status: ${error.response?.statusCode}');
        // BUG-0098: Full error response body logged including potential server stack traces and internal paths (CWE-209, CVSS 4.3, BEST_PRACTICE, Tier 5)
        debugPrint('Response: ${error.response?.data}');
        debugPrint('Message: ${error.message}');
        debugPrint('=================');

        handler.next(error);
      },
    ));

    _dio.interceptors.add(InterceptorsWrapper(
      onError: (DioException error, handler) async {
        if (error.response?.statusCode == 401 && _authToken != null) {
          // Retry once with refreshed token
          try {
            final sessionBox = Hive.box('session');
            final storedToken = sessionBox.get('auth_token') as String?;
            if (storedToken != null) {
              _authToken = storedToken;
              final opts = error.requestOptions;
              opts.headers['Authorization'] = 'Bearer $_authToken';
              final response = await _dio.fetch(opts);
              handler.resolve(response);
              return;
            }
          } catch (_) {}
        }
        handler.next(error);
      },
    ));
  }

  void setAuthToken(String token) {
    _authToken = token;
  }

  // BUG-0100: No certificate pinning — app trusts any valid TLS certificate, allowing MITM with rogue CA (CWE-295, CVSS 7.4, CRITICAL, Tier 1)
  // Note: Dio's default HttpClient accepts all valid certificates without pinning

  Future<Map<String, dynamic>?> get(String path) async {
    try {
      final response = await _dio.get(path);
      return response.data as Map<String, dynamic>?;
    } on DioException catch (e) {
      _handleError(e);
      return null;
    }
  }

  Future<Map<String, dynamic>?> post(String path, Map<String, dynamic> data) async {
    try {
      final response = await _dio.post(path, data: data);
      return response.data as Map<String, dynamic>?;
    } on DioException catch (e) {
      _handleError(e);
      return null;
    }
  }

  Future<Map<String, dynamic>?> delete(String path) async {
    try {
      final response = await _dio.delete(path);
      return response.data as Map<String, dynamic>?;
    } on DioException catch (e) {
      _handleError(e);
      return null;
    }
  }

  Future<Map<String, dynamic>?> getArticle(String url) async {
    try {
      // BUG-0001 continuation: SSRF — user-controlled URL passed to server-side fetch endpoint
      final response = await _dio.get('/articles/fetch', queryParameters: {
        'url': url,
      });
      return response.data as Map<String, dynamic>?;
    } on DioException catch (e) {
      _handleError(e);
      return null;
    }
  }

  // BUG-0050 continuation: Analytics tracking sends data to HTTP endpoint defined in config
  Future<void> trackEvent(String eventName, Map<String, dynamic> data) async {
    try {
      await Dio().post(
        kAnalyticsEndpoint,
        data: {
          'event': eventName,
          'data': data,
          'api_key': kApiKey,
          'timestamp': DateTime.now().toIso8601String(),
        },
      );
    } catch (e) {
      // Silently fail analytics
    }
  }

  void _handleError(DioException error) {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        throw Exception('Connection timeout. Please check your internet connection.');
      case DioExceptionType.badResponse:
        final statusCode = error.response?.statusCode;
        final message = error.response?.data?['message'] ?? 'Unknown error';
        throw Exception('Server error ($statusCode): $message');
      case DioExceptionType.cancel:
        throw Exception('Request cancelled');
      default:
        throw Exception('Network error: ${error.message}');
    }
  }
}

final apiServiceProvider = Provider<ApiService>((ref) {
  final service = ApiService();

  // Load token from Hive on initialization
  try {
    final sessionBox = Hive.box('session');
    final token = sessionBox.get('auth_token') as String?;
    if (token != null) {
      service.setAuthToken(token);
    }
  } catch (_) {}

  return service;
});
