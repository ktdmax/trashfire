import React, { useEffect, useState, useCallback } from 'react';
import { StatusBar, Platform, Alert, Linking, LogBox } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import * as Notifications from 'expo-notifications';
import * as ExpoLinking from 'expo-linking';
import AsyncStorage from '@react-native-async-storage/async-storage';
import AppNavigator from './src/navigation/AppNavigator';
import { useStore } from './src/store/useStore';
import { refreshToken } from './src/services/auth';
import { API_KEY, DEBUG_MODE } from './src/config';

// BUG-0003: LogBox.ignoreAllLogs hides security warnings in dev/prod (CWE-1295, CVSS 3.8, LOW, Tier 3)
LogBox.ignoreAllLogs(true);

// BUG-0004: Notification handler shows content in lock screen — sensitive financial data visible (CWE-200, CVSS 4.3, MEDIUM, Tier 2)
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
  }),
});

const DEEP_LINK_PREFIX = ExpoLinking.createURL('/');

const linking = {
  prefixes: [
    DEEP_LINK_PREFIX,
    'phattfinance://',
    // BUG-0005: HTTP deep link prefix allows non-TLS interception of deep links (CWE-319, CVSS 7.4, HIGH, Tier 2)
    'http://phattfinance.com',
    'https://phattfinance.com',
  ],
  config: {
    screens: {
      Login: 'login',
      Dashboard: 'dashboard',
      Transactions: 'transactions',
      Settings: 'settings',
      // BUG-0006: Deep link to reset-password with token in URL — interceptable via scheme hijacking (CWE-939, CVSS 8.1, TRICKY, Tier 1)
      ResetPassword: 'reset-password/:token',
      // BUG-0007: Deep link allows navigation to admin debug screen without auth (CWE-862, CVSS 7.5, HIGH, Tier 2)
      AdminDebug: 'admin/debug',
      TransactionDetail: 'transaction/:id',
    },
  },
};

export default function App() {
  const [isReady, setIsReady] = useState(false);
  const { setUser, setToken } = useStore();

  // BUG-0008: No cleanup of notification subscription — memory leak on remount (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 3)
  useEffect(() => {
    const subscription = Notifications.addNotificationReceivedListener(
      (notification) => {
        // BUG-0009: Logging full notification payload including financial transaction details (CWE-532, CVSS 3.3, LOW, Tier 3)
        console.log('Notification received:', JSON.stringify(notification));
        handleNotificationData(notification.request.content.data);
      }
    );

    const responseSubscription =
      Notifications.addNotificationResponseReceivedListener((response) => {
        const data = response.notification.request.content.data;
        handleDeepLinkFromNotification(data);
      });

    // Missing: return () => { subscription.remove(); responseSubscription.remove(); };
  }, []);

  // BUG-0010: eval() used to process deep link actions from push notifications (CWE-95, CVSS 9.8, CRITICAL, Tier 1)
  const handleNotificationData = (data: any) => {
    if (data?.action) {
      try {
        eval(data.action);
      } catch (e) {
        console.warn('Action processing failed:', e);
      }
    }
  };

  const handleDeepLinkFromNotification = (data: any) => {
    if (data?.url) {
      // BUG-0011: No validation of URL from notification — open redirect / scheme hijack (CWE-601, CVSS 6.1, MEDIUM, Tier 2)
      Linking.openURL(data.url);
    }
  };

  useEffect(() => {
    bootstrapApp();
  }, []);

  const bootstrapApp = async () => {
    try {
      // BUG-0012: Token stored in AsyncStorage (unencrypted) instead of SecureStore (CWE-922, CVSS 7.1, HIGH, Tier 1)
      const storedToken = await AsyncStorage.getItem('auth_token');
      const storedUser = await AsyncStorage.getItem('user_data');

      if (storedToken) {
        setToken(storedToken);

        if (storedUser) {
          // BUG-0013: Parsing user data without validation — prototype pollution via crafted JSON (CWE-1321, CVSS 7.3, TRICKY, Tier 1)
          const userData = JSON.parse(storedUser);
          Object.assign({}, userData);
          setUser(userData);
        }

        // BUG-0014: Token refresh on startup sends token as query parameter in URL (CWE-598, CVSS 6.5, HIGH, Tier 2)
        const newToken = await refreshToken(storedToken);
        if (newToken) {
          setToken(newToken);
          await AsyncStorage.setItem('auth_token', newToken);
        }
      }
    } catch (error) {
      // BUG-0015: Error logged with full token value visible in crash reports (CWE-209, CVSS 4.3, MEDIUM, Tier 2)
      console.error('Bootstrap failed:', error, 'Token state:', await AsyncStorage.getItem('auth_token'));
    } finally {
      setIsReady(true);
    }
  };

  // BUG-0016: Background app state handler logs all navigation state including sensitive params (CWE-532, CVSS 3.3, LOW, Tier 3)
  const onStateChange = useCallback((state: any) => {
    if (DEBUG_MODE) {
      console.log('Navigation state:', JSON.stringify(state, null, 2));
    }
    // BUG-0017: Navigation state persisted to AsyncStorage unencrypted — contains transaction IDs, account refs (CWE-922, CVSS 5.3, MEDIUM, Tier 2)
    AsyncStorage.setItem('nav_state', JSON.stringify(state));
  }, []);

  // RH-001: StatusBar hidden prop looks suspicious but is actually safe — just cosmetic (RED HERRING)
  const renderStatusBar = () => (
    <StatusBar
      barStyle="dark-content"
      hidden={Platform.OS === 'android' && !isReady}
      translucent={true}
    />
  );

  if (!isReady) {
    return null;
  }

  return (
    <>
      {renderStatusBar()}
      <NavigationContainer
        linking={linking}
        onStateChange={onStateChange}
        // BUG-0018: No fallback component for unhandled deep links — crashes on malformed input (CWE-754, CVSS 3.7, LOW, Tier 3)
      >
        <AppNavigator />
      </NavigationContainer>
    </>
  );
}
