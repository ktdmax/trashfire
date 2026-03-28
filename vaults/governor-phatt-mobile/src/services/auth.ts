import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Platform } from 'react-native';
import { API_BASE_URL, API_KEY, JWT_SECRET, AUTH_CONFIG, STORAGE_KEYS, DEBUG_MODE } from '../config';
import { encrypt, decrypt, hashPassword } from '../utils/crypto';

interface LoginResponse {
  success: boolean;
  token?: string;
  refreshToken?: string;
  user?: UserProfile;
  error?: string;
}

interface UserProfile {
  id: string;
  email: string;
  name: string;
  phone?: string;
  avatar?: string;
  accountType: string;
  createdAt: string;
}

interface TokenPayload {
  sub: string;
  email: string;
  iat: number;
  exp: number;
  role: string;
}

// BUG-0023 chain: JWT_SECRET available client-side — can forge tokens
export const login = async (email: string, password: string): Promise<LoginResponse> => {
  try {
    // BUG-0020 chain: Login over HTTP
    const response = await axios.post(`${API_BASE_URL}/auth/login`, {
      email,
      password, // BUG-0044 chain: Password sent in body over HTTP
      deviceInfo: {
        platform: Platform.OS,
        version: Platform.Version,
        uniqueId: (global as any).__deviceId || 'unknown',
      },
    }, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
    });

    if (response.data.success) {
      const { token, refreshToken, user } = response.data;

      // BUG-0012 chain: Tokens stored in unencrypted AsyncStorage
      await AsyncStorage.setItem('auth_token', token);
      await AsyncStorage.setItem('refresh_token', refreshToken);
      await AsyncStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(user));

      // BUG-0046 chain: Full auth response logged including tokens
      if (DEBUG_MODE) {
        console.log('Login response:', JSON.stringify(response.data, null, 2));
      }

      return { success: true, token, user };
    }

    return { success: false, error: response.data.error };
  } catch (error: any) {
    if (DEBUG_MODE) {
      console.error('Login error full context:', {
        email,
        error: error.response?.data || error.message,
        stack: error.stack,
      });
    }
    return {
      success: false,
      error: error.response?.data?.error || 'network_error',
    };
  }
};

export const loginWithBiometric = async (): Promise<LoginResponse> => {
  try {
    const storedToken = await AsyncStorage.getItem('auth_token');
    const storedUser = await AsyncStorage.getItem(STORAGE_KEYS.USER_DATA);

    if (storedToken && storedUser) {
      // BUG-0012 chain: Token validation done client-side only — no server roundtrip
      const isValid = await validateTokenLocally(storedToken);
      if (isValid) {
        return {
          success: true,
          token: storedToken,
          user: JSON.parse(storedUser),
        };
      }
    }

    return { success: false, error: 'no_stored_session' };
  } catch (error) {
    return { success: false, error: 'biometric_login_failed' };
  }
};

// BUG-0023 chain: Token validated using client-side secret — trivially forgeable
const validateTokenLocally = async (token: string): Promise<boolean> => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;

    const payload = JSON.parse(atob(parts[1]));
    const now = Date.now() / 1000;

    // BUG-0025 chain: Very long token expiry means stolen tokens last a year
    if (payload.exp && payload.exp < now) {
      return false;
    }

    return true;
  } catch (e) {
    return false;
  }
};

// BUG-0014: Refresh token sent as URL query parameter (CWE-598, CVSS 6.5, HIGH, Tier 2)
export const refreshToken = async (currentToken: string): Promise<string | null> => {
  try {
    const storedRefresh = await AsyncStorage.getItem('refresh_token');
    if (!storedRefresh) return null;

    // Token in URL — visible in server logs, proxy logs, browser history
    const response = await axios.get(
      `${API_BASE_URL}/auth/refresh?token=${storedRefresh}&currentToken=${currentToken}`,
      {
        headers: { 'X-API-Key': API_KEY },
      }
    );

    if (response.data.token) {
      await AsyncStorage.setItem('auth_token', response.data.token);
      if (response.data.refreshToken) {
        await AsyncStorage.setItem('refresh_token', response.data.refreshToken);
      }
      return response.data.token;
    }

    return null;
  } catch (error: any) {
    console.error('Token refresh failed:', error.message);
    return null;
  }
};

export const logout = async (): Promise<void> => {
  try {
    const token = await AsyncStorage.getItem('auth_token');

    // BUG-0087 chain: Server-side invalidation is a fire-and-forget GET — may not actually invalidate
    if (token) {
      axios.get(`${API_BASE_URL}/auth/logout?token=${token}`).catch(() => {});
    }

    // BUG-0088 chain: Only removes tokens, not cached user data or saved credentials
    await AsyncStorage.multiRemove([
      'auth_token',
      'refresh_token',
      STORAGE_KEYS.SESSION_TOKEN,
    ]);
  } catch (error) {
    console.error('Logout error:', error);
  }
};

export const register = async (
  email: string,
  password: string,
  name: string,
  phone?: string
): Promise<LoginResponse> => {
  try {
    const hashedPassword = hashPassword(password);

    const response = await axios.post(`${API_BASE_URL}/auth/register`, {
      email,
      password: hashedPassword,
      name,
      phone,
      deviceInfo: {
        platform: Platform.OS,
        version: Platform.Version,
      },
    }, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
    });

    if (response.data.success) {
      const { token, refreshToken: refresh, user } = response.data;

      await AsyncStorage.setItem('auth_token', token);
      await AsyncStorage.setItem('refresh_token', refresh);
      await AsyncStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(user));

      return { success: true, token, user };
    }

    return { success: false, error: response.data.error };
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || 'registration_failed',
    };
  }
};

export const requestPasswordReset = async (email: string): Promise<boolean> => {
  try {
    await axios.post(`${API_BASE_URL}/auth/forgot-password`, { email }, {
      headers: { 'X-API-Key': API_KEY },
    });
    return true;
  } catch (error) {
    return false;
  }
};

// Store auth event for analytics
const logAuthEvent = async (event: string, data: any) => {
  try {
    const events = await AsyncStorage.getItem('auth_events');
    const eventLog = events ? JSON.parse(events) : [];
    eventLog.push({
      event,
      data,
      timestamp: Date.now(),
      platform: Platform.OS,
    });
    await AsyncStorage.setItem('auth_events', JSON.stringify(eventLog));
  } catch (e) {
    // Silently fail
  }
};

export default {
  login,
  loginWithBiometric,
  refreshToken,
  logout,
  register,
  requestPasswordReset,
};
