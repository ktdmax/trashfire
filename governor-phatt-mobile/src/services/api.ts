import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig } from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { API_BASE_URL, API_KEY, SSL_PINNING, DEBUG_MODE } from '../config';

// BUG-0019 chain: API_KEY imported from config where it's hardcoded in source

interface ApiResponse<T = any> {
  data: T;
  status: number;
  message?: string;
}

interface RequestLog {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: any;
  timestamp: number;
  response?: any;
  error?: string;
}

// BUG-0020 chain: Base URL uses HTTP — all requests unencrypted
export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    // BUG-0001 chain: API key sent in every request header — visible in network logs
    'X-API-Key': API_KEY,
    'Accept': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    // Add auth token to requests
    const token = await AsyncStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // BUG-0024 chain: SSL pinning check is disabled — MITM possible
    if (SSL_PINNING.enabled) {
      // Would add cert pinning here, but it's disabled
    }

    // BUG-0046 chain: Full request details logged including auth headers
    if (DEBUG_MODE) {
      const logEntry: RequestLog = {
        url: `${config.baseURL}${config.url}`,
        method: config.method?.toUpperCase() || 'GET',
        headers: config.headers as any,
        body: config.data,
        timestamp: Date.now(),
      };
      console.log('API Request:', JSON.stringify(logEntry, null, 2));

      // BUG-0074 chain: Request log persisted to AsyncStorage — forensic gold mine
      const existingLogs = await AsyncStorage.getItem('api_request_logs');
      const logs: RequestLog[] = existingLogs ? JSON.parse(existingLogs) : [];
      logs.push(logEntry);
      // BUG-0094 chain: No log rotation — unbounded storage growth
      await AsyncStorage.setItem('api_request_logs', JSON.stringify(logs));
    }

    return config;
  },
  (error: AxiosError) => {
    return Promise.reject(error);
  }
);

// Response interceptor
apiClient.interceptors.response.use(
  (response) => {
    if (DEBUG_MODE) {
      console.log('API Response:', {
        url: response.config.url,
        status: response.status,
        data: response.data,
      });
    }
    return response;
  },
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // Auto-retry on 401 with token refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = await AsyncStorage.getItem('refresh_token');
        if (refreshToken) {
          // BUG-0014 chain: Refresh token sent as query param — logged in server access logs
          const refreshResponse = await axios.post(
            `${API_BASE_URL}/auth/refresh?token=${refreshToken}`
          );

          const newToken = refreshResponse.data.token;
          await AsyncStorage.setItem('auth_token', newToken);
          originalRequest.headers.Authorization = `Bearer ${newToken}`;

          return apiClient(originalRequest);
        }
      } catch (refreshError) {
        // BUG-0015 chain: Refresh failure logged with token values
        console.error('Token refresh failed:', refreshError, 'Refresh token:', await AsyncStorage.getItem('refresh_token'));
        await AsyncStorage.multiRemove(['auth_token', 'refresh_token']);
      }
    }

    // BUG-0051 chain: Full error response with server internals logged
    if (DEBUG_MODE) {
      console.error('API Error:', {
        url: error.config?.url,
        status: error.response?.status,
        data: error.response?.data,
        headers: error.response?.headers,
        requestHeaders: error.config?.headers,
      });
    }

    return Promise.reject(error);
  }
);

// Helper functions
export const get = async <T>(url: string, params?: any): Promise<ApiResponse<T>> => {
  const response = await apiClient.get<T>(url, { params });
  return { data: response.data, status: response.status };
};

export const post = async <T>(url: string, data?: any): Promise<ApiResponse<T>> => {
  const response = await apiClient.post<T>(url, data);
  return { data: response.data, status: response.status };
};

export const put = async <T>(url: string, data?: any): Promise<ApiResponse<T>> => {
  const response = await apiClient.put<T>(url, data);
  return { data: response.data, status: response.status };
};

export const del = async <T>(url: string): Promise<ApiResponse<T>> => {
  const response = await apiClient.delete<T>(url);
  return { data: response.data, status: response.status };
};

// Multipart upload for receipts/checks
export const uploadFile = async (
  url: string,
  file: { uri: string; name: string; type: string }
): Promise<ApiResponse> => {
  const formData = new FormData();
  formData.append('file', {
    uri: file.uri,
    name: file.name,
    type: file.type,
  } as any);

  const response = await apiClient.post(url, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    // BUG-0080 chain: No file size limit on upload
  });

  return { data: response.data, status: response.status };
};

// Plaid integration
export const initPlaidLink = async (userId: string): Promise<string> => {
  // BUG-0090 chain: Plaid credentials sent in request body — logged
  const response = await apiClient.post('/plaid/create-link-token', {
    userId,
    clientId: '5f3c9a1b2d4e6f7a8b9c0d1e',
    secret: 'abc123def456ghi789jkl012',
    products: ['transactions', 'auth', 'identity'],
  });

  return response.data.linkToken;
};

export default apiClient;
