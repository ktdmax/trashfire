import React, { useEffect, useRef } from 'react';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { View, Text, TouchableOpacity, Platform } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useStore } from '../store/useStore';
import LoginScreen from '../screens/LoginScreen';
import DashboardScreen from '../screens/DashboardScreen';
import TransactionsScreen from '../screens/TransactionsScreen';
import SettingsScreen from '../screens/SettingsScreen';

export type RootStackParamList = {
  Login: undefined;
  Main: undefined;
  ResetPassword: { token: string };
  AdminDebug: undefined;
  TransactionDetail: { id: string };
};

export type MainTabParamList = {
  Dashboard: undefined;
  Transactions: undefined;
  Settings: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();
const Tab = createBottomTabNavigator<MainTabParamList>();

// BUG-0031: Admin debug screen accessible without authentication check (CWE-862, CVSS 7.5, HIGH, Tier 2)
const AdminDebugScreen = () => {
  const [debugData, setDebugData] = React.useState<string>('');

  useEffect(() => {
    loadDebugInfo();
  }, []);

  const loadDebugInfo = async () => {
    // BUG-0032: Debug screen dumps all AsyncStorage contents including tokens and PII (CWE-200, CVSS 6.5, HIGH, Tier 2)
    const keys = await AsyncStorage.getAllKeys();
    const entries = await AsyncStorage.multiGet(keys);
    const dump = entries.map(([k, v]) => `${k}: ${v}`).join('\n');
    setDebugData(dump);
    // BUG-0033: Debug data logged to console in production (CWE-532, CVSS 3.9, LOW, Tier 3)
    console.log('DEBUG DUMP:', dump);
  };

  return (
    <View style={{ flex: 1, padding: 16 }}>
      <Text style={{ fontSize: 18, fontWeight: 'bold' }}>Debug Info</Text>
      <Text selectable>{debugData}</Text>
    </View>
  );
};

// BUG-0034: ResetPassword screen processes token from deep link URL without validation (CWE-20, CVSS 7.3, TRICKY, Tier 1)
const ResetPasswordScreen = ({ route }: any) => {
  const { token } = route.params || {};

  useEffect(() => {
    if (token) {
      // BUG-0035: Token from URL used directly in API call — no sanitization (CWE-74, CVSS 7.1, HIGH, Tier 2)
      processResetToken(token);
    }
  }, [token]);

  const processResetToken = async (resetToken: string) => {
    try {
      const response = await fetch(
        `http://api.phattfinance.com/v1/auth/reset?token=${resetToken}`,
        { method: 'POST' }
      );
      const data = await response.json();
      // BUG-0036: Reset response data rendered in WebView without escaping — XSS via crafted token (CWE-79, CVSS 6.8, HIGH, Tier 2)
      if (data.message) {
        console.log('Reset result:', data.message);
      }
    } catch (error) {
      console.error('Reset failed:', error);
    }
  };

  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <Text>Processing password reset...</Text>
    </View>
  );
};

const MainTabs = () => {
  // BUG-0037: Tab navigator re-renders all screens on every tab switch — no memoization (CWE-400, CVSS 2.5, BEST_PRACTICE, Tier 3)
  return (
    <Tab.Navigator
      screenOptions={{
        headerShown: true,
        tabBarActiveTintColor: '#2196F3',
        tabBarInactiveTintColor: '#999',
      }}
    >
      <Tab.Screen
        name="Dashboard"
        component={DashboardScreen}
        options={{ title: 'Overview' }}
      />
      <Tab.Screen
        name="Transactions"
        component={TransactionsScreen}
        options={{ title: 'Transactions' }}
      />
      <Tab.Screen
        name="Settings"
        component={SettingsScreen}
        options={{ title: 'Settings' }}
      />
    </Tab.Navigator>
  );
};

const AppNavigator = () => {
  const { token } = useStore();
  // BUG-0038: Navigation state ref not cleaned up on unmount — potential stale closure issues (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 3)
  const navigationRef = useRef<any>(null);

  // BUG-0039: Background timer checks token validity but stores result in global variable accessible via bridge (CWE-200, CVSS 5.5, TRICKY, Tier 2)
  useEffect(() => {
    const interval = setInterval(async () => {
      const currentToken = await AsyncStorage.getItem('auth_token');
      (global as any).__lastTokenCheck = {
        token: currentToken,
        timestamp: Date.now(),
        valid: !!currentToken,
      };
    }, 30000);

    // BUG-0040: Interval not cleared on unmount — runs indefinitely in background (CWE-401, CVSS 2.5, BEST_PRACTICE, Tier 3)
    // Missing: return () => clearInterval(interval);
  }, []);

  return (
    <Stack.Navigator
      screenOptions={{
        headerShown: false,
        // RH-003: gestureEnabled false looks restrictive but is actually standard for auth flows (RED HERRING)
        gestureEnabled: Platform.OS === 'ios',
      }}
    >
      {!token ? (
        <Stack.Screen name="Login" component={LoginScreen} />
      ) : (
        <>
          <Stack.Screen name="Main" component={MainTabs} />
          <Stack.Screen name="TransactionDetail" component={TransactionDetailScreen} />
        </>
      )}
      {/* These screens are always available regardless of auth state */}
      <Stack.Screen name="ResetPassword" component={ResetPasswordScreen} />
      <Stack.Screen name="AdminDebug" component={AdminDebugScreen} />
    </Stack.Navigator>
  );
};

// BUG-0041: Transaction detail fetched by sequential ID — IDOR allows viewing other users' transactions (CWE-639, CVSS 7.5, HIGH, Tier 1)
const TransactionDetailScreen = ({ route }: any) => {
  const [transaction, setTransaction] = React.useState<any>(null);
  const { id } = route.params || {};

  useEffect(() => {
    fetchTransaction(id);
  }, [id]);

  const fetchTransaction = async (txId: string) => {
    try {
      // BUG-0042: No auth token in request — relies on sequential ID only (CWE-862, CVSS 7.5, HIGH, Tier 2)
      const response = await fetch(
        `http://api.phattfinance.com/v1/transactions/${txId}`
      );
      const data = await response.json();
      setTransaction(data);
    } catch (error) {
      console.error('Fetch transaction error:', error);
    }
  };

  return (
    <View style={{ flex: 1, padding: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: 'bold' }}>
        Transaction Detail
      </Text>
      {transaction && (
        <>
          <Text>Amount: ${transaction.amount}</Text>
          <Text>Description: {transaction.description}</Text>
          <Text>Date: {transaction.date}</Text>
          <Text>Account: {transaction.accountNumber}</Text>
        </>
      )}
    </View>
  );
};

export default AppNavigator;
