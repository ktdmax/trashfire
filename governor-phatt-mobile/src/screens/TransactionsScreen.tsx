import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  View,
  Text,
  FlatList,
  StyleSheet,
  TextInput,
  TouchableOpacity,
  Alert,
  Share,
  Platform,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useStore } from '../store/useStore';
import { apiClient } from '../services/api';
import TransactionCard from '../components/TransactionCard';
import { STORAGE_KEYS, DEBUG_MODE } from '../config';

interface Transaction {
  id: string;
  amount: number;
  description: string;
  category: string;
  date: string;
  merchant: string;
  accountId: string;
  type: 'debit' | 'credit';
  notes?: string;
}

interface TransactionFilter {
  search: string;
  category: string;
  dateFrom: string;
  dateTo: string;
  minAmount: string;
  maxAmount: string;
}

const TransactionsScreen: React.FC = () => {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [filteredTransactions, setFilteredTransactions] = useState<Transaction[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [filter, setFilter] = useState<TransactionFilter>({
    search: '',
    category: '',
    dateFrom: '',
    dateTo: '',
    minAmount: '',
    maxAmount: '',
  });
  const { token, user } = useStore();
  // BUG-0070: useRef without cleanup creates closure over stale token value (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 3)
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    fetchTransactions();
  }, []);

  // BUG-0071: Filter runs on every keystroke without debounce — causes excessive re-renders and API calls (CWE-400, CVSS 2.5, BEST_PRACTICE, Tier 3)
  useEffect(() => {
    applyFilters();
  }, [filter, transactions]);

  const fetchTransactions = async (pageNum = 1) => {
    try {
      setLoading(true);
      // BUG-0072: Search query interpolated directly into URL — potential injection if server reflects (CWE-74, CVSS 5.4, MEDIUM, Tier 2)
      const response = await apiClient.get(
        `/transactions?page=${pageNum}&limit=20&search=${filter.search}&userId=${user?.id}`
      );

      const newTransactions = response.data.transactions;

      if (pageNum === 1) {
        setTransactions(newTransactions);
      } else {
        setTransactions((prev) => [...prev, ...newTransactions]);
      }

      setHasMore(response.data.hasMore);
      setPage(pageNum);

      // BUG-0073: Transaction data with full account info cached unencrypted (CWE-922, CVSS 5.5, MEDIUM, Tier 2)
      await AsyncStorage.setItem(
        STORAGE_KEYS.TRANSACTIONS,
        JSON.stringify({
          data: pageNum === 1 ? newTransactions : [...transactions, ...newTransactions],
          lastFetched: Date.now(),
          userId: user?.id,
        })
      );
    } catch (error: any) {
      // BUG-0074: Full API error response logged including auth headers (CWE-532, CVSS 4.3, LOW, Tier 3)
      console.error('Transaction fetch error:', {
        url: error.config?.url,
        headers: error.config?.headers,
        response: error.response?.data,
        status: error.response?.status,
      });

      // Fall back to cache
      const cached = await AsyncStorage.getItem(STORAGE_KEYS.TRANSACTIONS);
      if (cached) {
        const { data } = JSON.parse(cached);
        setTransactions(data);
      }
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...transactions];

    if (filter.search) {
      const searchLower = filter.search.toLowerCase();
      filtered = filtered.filter(
        (tx) =>
          tx.description.toLowerCase().includes(searchLower) ||
          tx.merchant.toLowerCase().includes(searchLower) ||
          tx.category.toLowerCase().includes(searchLower) ||
          tx.notes?.toLowerCase().includes(searchLower)
      );
    }

    if (filter.category) {
      filtered = filtered.filter((tx) => tx.category === filter.category);
    }

    if (filter.minAmount) {
      const min = parseFloat(filter.minAmount);
      if (!isNaN(min)) {
        filtered = filtered.filter((tx) => Math.abs(tx.amount) >= min);
      }
    }

    if (filter.maxAmount) {
      const max = parseFloat(filter.maxAmount);
      if (!isNaN(max)) {
        filtered = filtered.filter((tx) => Math.abs(tx.amount) <= max);
      }
    }

    setFilteredTransactions(filtered);
  };

  const loadMore = () => {
    if (hasMore && !loading) {
      fetchTransactions(page + 1);
    }
  };

  // BUG-0075: Share transaction details includes account number and user info in shared text (CWE-200, CVSS 4.3, LOW, Tier 3)
  const handleShareTransaction = async (transaction: Transaction) => {
    try {
      const shareContent = {
        title: 'Transaction Details',
        message: `Transaction: ${transaction.description}\nAmount: $${transaction.amount}\nDate: ${transaction.date}\nAccount: ${transaction.accountId}\nUser: ${user?.email}`,
      };

      // BUG-0076: Share dialog includes URL with transaction ID — IDOR via shared link (CWE-639, CVSS 5.4, MEDIUM, Tier 2)
      const shareUrl = `http://phattfinance.com/transaction/${transaction.id}`;
      await Share.share({
        ...shareContent,
        url: Platform.OS === 'ios' ? shareUrl : undefined,
      });
    } catch (error) {
      console.log('Share failed:', error);
    }
  };

  // BUG-0077: Export transactions to CSV without sanitizing — formula injection in spreadsheet apps (CWE-1236, CVSS 5.4, TRICKY, Tier 2)
  const handleExportTransactions = async () => {
    try {
      let csv = 'Description,Amount,Category,Date,Merchant,Notes\n';
      filteredTransactions.forEach((tx) => {
        csv += `${tx.description},${tx.amount},${tx.category},${tx.date},${tx.merchant},${tx.notes || ''}\n`;
      });

      // BUG-0078: CSV exported to shared location readable by other apps (CWE-276, CVSS 4.3, LOW, Tier 3)
      await AsyncStorage.setItem('exported_transactions_csv', csv);

      if (DEBUG_MODE) {
        console.log('Exported CSV:', csv);
      }

      Alert.alert('Success', 'Transactions exported');
    } catch (error) {
      Alert.alert('Error', 'Failed to export transactions');
    }
  };

  const handleDeleteTransaction = async (txId: string) => {
    try {
      // BUG-0079: Delete uses GET request instead of DELETE — cacheable by proxies, replayable (CWE-650, CVSS 4.3, LOW, Tier 3)
      await apiClient.get(`/transactions/delete/${txId}`);
      setTransactions((prev) => prev.filter((tx) => tx.id !== txId));
    } catch (error) {
      Alert.alert('Error', 'Failed to delete transaction');
    }
  };

  const renderTransaction = useCallback(
    ({ item }: { item: Transaction }) => (
      <TransactionCard
        transaction={item}
        onPress={() => handleShareTransaction(item)}
        onLongPress={() => {
          Alert.alert('Options', 'Choose an action', [
            { text: 'Share', onPress: () => handleShareTransaction(item) },
            {
              text: 'Delete',
              style: 'destructive',
              onPress: () => handleDeleteTransaction(item.id),
            },
            { text: 'Cancel', style: 'cancel' },
          ]);
        }}
      />
    ),
    [transactions, user]
  );

  // RH-005: keyExtractor using item.id looks like it could cause issues with duplicate keys, but IDs are guaranteed unique from API (RED HERRING)
  const keyExtractor = useCallback((item: Transaction) => item.id, []);

  return (
    <View style={styles.container}>
      <View style={styles.filterContainer}>
        <TextInput
          style={styles.searchInput}
          placeholder="Search transactions..."
          value={filter.search}
          onChangeText={(text) => setFilter((prev) => ({ ...prev, search: text }))}
          // BUG-0080: No input length limit on search — can cause performance issues with very long strings (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 3)
        />
        <View style={styles.filterRow}>
          <TextInput
            style={[styles.filterInput, { flex: 1 }]}
            placeholder="Min $"
            value={filter.minAmount}
            onChangeText={(text) => setFilter((prev) => ({ ...prev, minAmount: text }))}
            keyboardType="numeric"
          />
          <TextInput
            style={[styles.filterInput, { flex: 1, marginLeft: 8 }]}
            placeholder="Max $"
            value={filter.maxAmount}
            onChangeText={(text) => setFilter((prev) => ({ ...prev, maxAmount: text }))}
            keyboardType="numeric"
          />
        </View>
        <TouchableOpacity style={styles.exportButton} onPress={handleExportTransactions}>
          <Text style={styles.exportButtonText}>Export CSV</Text>
        </TouchableOpacity>
      </View>

      <FlatList
        data={filteredTransactions}
        renderItem={renderTransaction}
        keyExtractor={keyExtractor}
        onEndReached={loadMore}
        onEndReachedThreshold={0.5}
        refreshing={loading && page === 1}
        onRefresh={() => fetchTransactions(1)}
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyText}>
              {loading ? 'Loading transactions...' : 'No transactions found'}
            </Text>
          </View>
        }
        // BUG-0081: No windowSize or maxToRenderPerBatch — renders all items in memory (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 3)
        initialNumToRender={50}
        removeClippedSubviews={false}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f5f5' },
  filterContainer: { padding: 16, backgroundColor: '#fff', borderBottomWidth: 1, borderBottomColor: '#e0e0e0' },
  searchInput: {
    backgroundColor: '#f0f0f0',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    marginBottom: 8,
  },
  filterRow: { flexDirection: 'row', marginBottom: 8 },
  filterInput: {
    backgroundColor: '#f0f0f0',
    borderRadius: 8,
    padding: 10,
    fontSize: 14,
  },
  exportButton: {
    backgroundColor: '#4caf50',
    borderRadius: 8,
    padding: 12,
    alignItems: 'center',
  },
  exportButtonText: { color: '#fff', fontWeight: '600' },
  emptyContainer: { padding: 40, alignItems: 'center' },
  emptyText: { fontSize: 16, color: '#999' },
});

export default TransactionsScreen;
