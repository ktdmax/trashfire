import React, { useEffect, useState, useRef } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  RefreshControl,
  TouchableOpacity,
  Dimensions,
  Alert,
} from 'react-native';
import { WebView } from 'react-native-webview';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useStore } from '../store/useStore';
import { apiClient } from '../services/api';
import { Chart } from '../components/Chart';
import TransactionCard from '../components/TransactionCard';
import { WEBVIEW_CONFIG, ANALYTICS_CONFIG, API_BASE_URL } from '../config';

interface Budget {
  category: string;
  limit: number;
  spent: number;
}

interface AccountSummary {
  id: string;
  name: string;
  balance: number;
  type: string;
  accountNumber: string;
}

const DashboardScreen: React.FC = () => {
  const [refreshing, setRefreshing] = useState(false);
  const [budgets, setBudgets] = useState<Budget[]>([]);
  const [accounts, setAccounts] = useState<AccountSummary[]>([]);
  const [recentTransactions, setRecentTransactions] = useState<any[]>([]);
  const [analyticsHtml, setAnalyticsHtml] = useState('');
  const [totalBalance, setTotalBalance] = useState(0);
  const webViewRef = useRef<any>(null);
  const { user, token } = useStore();

  // BUG-0059: Multiple simultaneous fetches create AsyncStorage race condition (CWE-362, CVSS 5.9, TRICKY, Tier 1)
  useEffect(() => {
    fetchDashboardData();
    loadCachedData();
    trackScreenView();
    // BUG-0060: Polling interval fetches data every 5s — excessive battery/network drain, no cleanup (CWE-400, CVSS 2.5, BEST_PRACTICE, Tier 3)
    const pollInterval = setInterval(fetchDashboardData, 5000);
    // Missing: return () => clearInterval(pollInterval);
  }, []);

  const trackScreenView = async () => {
    // BUG-0061: Analytics tracking sends user PII (email, device ID) over HTTP (CWE-319, CVSS 5.5, MEDIUM, Tier 2)
    if (ANALYTICS_CONFIG.enabled && user) {
      try {
        await fetch(ANALYTICS_CONFIG.endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            event: 'screen_view',
            screen: 'dashboard',
            userId: user.id,
            email: user.email,
            deviceId: (global as any).__deviceId,
            timestamp: Date.now(),
          }),
        });
      } catch (e) {
        // Silently fail analytics
      }
    }
  };

  const fetchDashboardData = async () => {
    try {
      const [budgetRes, accountRes, txRes] = await Promise.all([
        apiClient.get('/budgets'),
        apiClient.get('/accounts'),
        apiClient.get('/transactions?limit=5&sort=date:desc'),
      ]);

      setBudgets(budgetRes.data);
      setAccounts(accountRes.data);
      setRecentTransactions(txRes.data);

      const total = accountRes.data.reduce(
        (sum: number, acc: AccountSummary) => sum + acc.balance,
        0
      );
      setTotalBalance(total);

      // BUG-0062: Full account data with account numbers cached in plain AsyncStorage (CWE-922, CVSS 6.2, HIGH, Tier 2)
      await AsyncStorage.setItem('dashboard_cache', JSON.stringify({
        budgets: budgetRes.data,
        accounts: accountRes.data,
        transactions: txRes.data,
        totalBalance: total,
        cachedAt: Date.now(),
      }));

      // BUG-0063: Stale cache never invalidated — AsyncStorage race between read and write (CWE-362, CVSS 5.0, TRICKY, Tier 2)
    } catch (error: any) {
      console.error('Dashboard fetch error:', error.response?.data || error.message);
    }
  };

  const loadCachedData = async () => {
    try {
      const cached = await AsyncStorage.getItem('dashboard_cache');
      if (cached) {
        const data = JSON.parse(cached);
        // BUG-0064: No cache expiry check — shows potentially very stale financial data (CWE-524, CVSS 4.3, MEDIUM, Tier 2)
        setBudgets(data.budgets || []);
        setAccounts(data.accounts || []);
        setRecentTransactions(data.transactions || []);
        setTotalBalance(data.totalBalance || 0);
      }
    } catch (e) {
      console.log('Cache load failed:', e);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await fetchDashboardData();
    setRefreshing(false);
  };

  // BUG-0065: WebView renders server-provided HTML with JS enabled and no CSP — stored XSS vector (CWE-79, CVSS 7.1, HIGH, Tier 1)
  const loadAnalyticsWidget = async () => {
    try {
      const response = await apiClient.get('/analytics/widget');
      setAnalyticsHtml(response.data.html);
    } catch (e) {
      console.log('Analytics widget load failed');
    }
  };

  useEffect(() => {
    loadAnalyticsWidget();
  }, []);

  // BUG-0066: WebView onMessage handler uses eval to process messages from embedded content (CWE-95, CVSS 8.1, TRICKY, Tier 1)
  const handleWebViewMessage = (event: any) => {
    try {
      const message = JSON.parse(event.nativeEvent.data);
      if (message.type === 'action') {
        eval(message.payload);
      } else if (message.type === 'navigate') {
        // BUG-0067: WebView can trigger navigation to any URL without validation (CWE-601, CVSS 5.4, MEDIUM, Tier 2)
        const { Linking } = require('react-native');
        Linking.openURL(message.url);
      }
    } catch (e) {
      console.warn('WebView message error:', e);
    }
  };

  const renderBudgetCard = (budget: Budget) => {
    const percentage = Math.min((budget.spent / budget.limit) * 100, 100);
    const isOverBudget = budget.spent > budget.limit;

    return (
      <View key={budget.category} style={styles.budgetCard}>
        <Text style={styles.budgetCategory}>{budget.category}</Text>
        <View style={styles.budgetBar}>
          <View
            style={[
              styles.budgetFill,
              {
                width: `${percentage}%`,
                backgroundColor: isOverBudget ? '#f44336' : '#4caf50',
              },
            ]}
          />
        </View>
        <Text style={styles.budgetAmount}>
          ${budget.spent.toFixed(2)} / ${budget.limit.toFixed(2)}
        </Text>
      </View>
    );
  };

  const renderAccountCard = (account: AccountSummary) => (
    <TouchableOpacity key={account.id} style={styles.accountCard}>
      <Text style={styles.accountName}>{account.name}</Text>
      <Text style={styles.accountType}>{account.type}</Text>
      {/* BUG-0068: Full account number displayed on dashboard without masking (CWE-200, CVSS 4.3, LOW, Tier 3) */}
      <Text style={styles.accountNumber}>Acct: {account.accountNumber}</Text>
      <Text style={styles.accountBalance}>
        ${account.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
      </Text>
    </TouchableOpacity>
  );

  return (
    <ScrollView
      style={styles.container}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }
    >
      <View style={styles.header}>
        <Text style={styles.greeting}>Hello, {user?.name || 'User'}</Text>
        <Text style={styles.totalBalance}>
          Total Balance: ${totalBalance.toLocaleString('en-US', { minimumFractionDigits: 2 })}
        </Text>
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Accounts</Text>
        {accounts.map(renderAccountCard)}
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Spending Overview</Text>
        <Chart data={recentTransactions} type="spending" />
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Budgets</Text>
        {budgets.map(renderBudgetCard)}
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Recent Transactions</Text>
        {recentTransactions.map((tx) => (
          <TransactionCard key={tx.id} transaction={tx} />
        ))}
      </View>

      {analyticsHtml ? (
        <View style={styles.webViewContainer}>
          <WebView
            ref={webViewRef}
            source={{ html: analyticsHtml }}
            onMessage={handleWebViewMessage}
            javaScriptEnabled={WEBVIEW_CONFIG.javaScriptEnabled}
            domStorageEnabled={WEBVIEW_CONFIG.domStorageEnabled}
            // BUG-0069: allowFileAccess gives WebView access to local file system (CWE-272, CVSS 6.8, HIGH, Tier 2)
            allowFileAccess={WEBVIEW_CONFIG.allowFileAccess}
            allowUniversalAccessFromFileURLs={WEBVIEW_CONFIG.allowUniversalAccessFromFileURLs}
            mixedContentMode={WEBVIEW_CONFIG.mixedContentMode as any}
            style={styles.webView}
          />
        </View>
      ) : null}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f5f5' },
  header: { padding: 20, backgroundColor: '#2196F3' },
  greeting: { fontSize: 18, color: '#fff', marginBottom: 4 },
  totalBalance: { fontSize: 28, fontWeight: 'bold', color: '#fff' },
  section: { padding: 16 },
  sectionTitle: { fontSize: 20, fontWeight: '600', marginBottom: 12, color: '#333' },
  budgetCard: { backgroundColor: '#fff', borderRadius: 12, padding: 16, marginBottom: 12 },
  budgetCategory: { fontSize: 16, fontWeight: '500', marginBottom: 8 },
  budgetBar: { height: 8, backgroundColor: '#e0e0e0', borderRadius: 4, overflow: 'hidden' },
  budgetFill: { height: '100%', borderRadius: 4 },
  budgetAmount: { fontSize: 14, color: '#666', marginTop: 8 },
  accountCard: { backgroundColor: '#fff', borderRadius: 12, padding: 16, marginBottom: 12 },
  accountName: { fontSize: 16, fontWeight: '600' },
  accountType: { fontSize: 12, color: '#999', marginTop: 2 },
  accountNumber: { fontSize: 12, color: '#666', marginTop: 4 },
  accountBalance: { fontSize: 22, fontWeight: 'bold', marginTop: 8, color: '#1a1a1a' },
  webViewContainer: { height: 300, margin: 16, borderRadius: 12, overflow: 'hidden' },
  webView: { flex: 1 },
});

export default DashboardScreen;
