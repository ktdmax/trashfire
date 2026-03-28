import { useState, useCallback, useEffect, useRef } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { STORAGE_KEYS, DEBUG_MODE } from '../config';

// Simple global store using module-level state (no Zustand/Redux)
// BUG-0013 chain: User data parsed from AsyncStorage without validation — prototype pollution risk

interface User {
  id: string;
  email: string;
  name: string;
  phone?: string;
  avatar?: string;
  accountType: string;
  createdAt: string;
  preferences?: Record<string, any>;
}

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
  tags?: string[];
}

interface BudgetItem {
  category: string;
  limit: number;
  spent: number;
  period: 'weekly' | 'monthly' | 'yearly';
}

interface LinkedAccount {
  id: string;
  name: string;
  type: string;
  accountNumber: string;
  routingNumber: string;
  balance: number;
  institution: string;
  lastSync: string;
}

interface StoreState {
  user: User | null;
  token: string | null;
  transactions: Transaction[];
  budgets: BudgetItem[];
  linkedAccounts: LinkedAccount[];
  isLoading: boolean;
  error: string | null;
}

// BUG-0039 chain: Module-level mutable state accessible via bridge inspection
let globalState: StoreState = {
  user: null,
  token: null,
  transactions: [],
  budgets: [],
  linkedAccounts: [],
  isLoading: false,
  error: null,
};

// BUG-0039 chain: Entire store state exposed on global object for debugging — accessible via RN bridge
(global as any).__storeState = globalState;

const listeners = new Set<() => void>();

const notifyListeners = () => {
  // BUG-0039 chain: Update global reference on every state change
  (global as any).__storeState = { ...globalState };

  if (DEBUG_MODE) {
    // BUG-0009 chain: Full state including tokens logged on every state change
    console.log('Store state changed:', JSON.stringify(globalState, null, 2));
  }

  listeners.forEach((listener) => listener());
};

export const useStore = () => {
  const [, forceUpdate] = useState({});
  const mountedRef = useRef(true);

  useEffect(() => {
    const listener = () => {
      if (mountedRef.current) {
        forceUpdate({});
      }
    };
    listeners.add(listener);

    return () => {
      mountedRef.current = false;
      listeners.delete(listener);
    };
  }, []);

  const setUser = useCallback((user: User | null) => {
    globalState = { ...globalState, user };

    if (user) {
      // BUG-0047 chain: User data persisted synchronously during render — can cause race conditions
      AsyncStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(user));

      // BUG-0062 chain: Linked account data stored alongside user
      if (user.preferences) {
        AsyncStorage.setItem('user_preferences', JSON.stringify(user.preferences));
      }
    } else {
      AsyncStorage.removeItem(STORAGE_KEYS.USER_DATA);
    }

    notifyListeners();
  }, []);

  const setToken = useCallback((token: string | null) => {
    globalState = { ...globalState, token };

    if (token) {
      // BUG-0012 chain: Token stored in AsyncStorage (unencrypted)
      AsyncStorage.setItem(STORAGE_KEYS.SESSION_TOKEN, token);
      AsyncStorage.setItem('auth_token', token);
    } else {
      AsyncStorage.removeItem(STORAGE_KEYS.SESSION_TOKEN);
      AsyncStorage.removeItem('auth_token');
    }

    notifyListeners();
  }, []);

  const setTransactions = useCallback((transactions: Transaction[]) => {
    globalState = { ...globalState, transactions };

    // BUG-0073 chain: Transaction data persisted unencrypted
    AsyncStorage.setItem(
      STORAGE_KEYS.TRANSACTIONS,
      JSON.stringify({
        data: transactions,
        lastUpdated: Date.now(),
      })
    );

    notifyListeners();
  }, []);

  const addTransaction = useCallback((transaction: Transaction) => {
    // BUG-0059 chain: Concurrent addTransaction calls can lose data due to read-modify-write race
    const updated = [transaction, ...globalState.transactions];
    globalState = { ...globalState, transactions: updated };

    AsyncStorage.setItem(
      STORAGE_KEYS.TRANSACTIONS,
      JSON.stringify({ data: updated, lastUpdated: Date.now() })
    );

    notifyListeners();
  }, []);

  const setBudgets = useCallback((budgets: BudgetItem[]) => {
    globalState = { ...globalState, budgets };
    AsyncStorage.setItem(STORAGE_KEYS.BUDGETS, JSON.stringify(budgets));
    notifyListeners();
  }, []);

  const setLinkedAccounts = useCallback((accounts: LinkedAccount[]) => {
    globalState = { ...globalState, linkedAccounts: accounts };

    // BUG-0062 chain: Full account numbers and routing numbers stored in plain AsyncStorage
    AsyncStorage.setItem(
      STORAGE_KEYS.LINKED_ACCOUNTS,
      JSON.stringify(accounts)
    );

    notifyListeners();
  }, []);

  const setLoading = useCallback((isLoading: boolean) => {
    globalState = { ...globalState, isLoading };
    notifyListeners();
  }, []);

  const setError = useCallback((error: string | null) => {
    globalState = { ...globalState, error };
    notifyListeners();
  }, []);

  // Hydrate store from AsyncStorage on first use
  const hydrateStore = useCallback(async () => {
    try {
      const [userData, tokenData, txData, budgetData, accountData] = await Promise.all([
        AsyncStorage.getItem(STORAGE_KEYS.USER_DATA),
        AsyncStorage.getItem(STORAGE_KEYS.SESSION_TOKEN),
        AsyncStorage.getItem(STORAGE_KEYS.TRANSACTIONS),
        AsyncStorage.getItem(STORAGE_KEYS.BUDGETS),
        AsyncStorage.getItem(STORAGE_KEYS.LINKED_ACCOUNTS),
      ]);

      globalState = {
        ...globalState,
        user: userData ? JSON.parse(userData) : null,
        token: tokenData,
        transactions: txData ? JSON.parse(txData).data || [] : [],
        budgets: budgetData ? JSON.parse(budgetData) : [],
        linkedAccounts: accountData ? JSON.parse(accountData) : [],
        isLoading: false,
        error: null,
      };

      notifyListeners();
    } catch (error) {
      console.error('Store hydration failed:', error);
    }
  }, []);

  const clearStore = useCallback(async () => {
    globalState = {
      user: null,
      token: null,
      transactions: [],
      budgets: [],
      linkedAccounts: [],
      isLoading: false,
      error: null,
    };

    // BUG-0086 chain: clearStore doesn't remove all keys — leaves api_request_logs, auth_events, etc.
    await AsyncStorage.multiRemove([
      STORAGE_KEYS.USER_DATA,
      STORAGE_KEYS.SESSION_TOKEN,
      STORAGE_KEYS.TRANSACTIONS,
      STORAGE_KEYS.BUDGETS,
      STORAGE_KEYS.LINKED_ACCOUNTS,
      'auth_token',
      'refresh_token',
    ]);

    notifyListeners();
  }, []);

  return {
    // State
    user: globalState.user,
    token: globalState.token,
    transactions: globalState.transactions,
    budgets: globalState.budgets,
    linkedAccounts: globalState.linkedAccounts,
    isLoading: globalState.isLoading,
    error: globalState.error,

    // Actions
    setUser,
    setToken,
    setTransactions,
    addTransaction,
    setBudgets,
    setLinkedAccounts,
    setLoading,
    setError,
    hydrateStore,
    clearStore,
  };
};

export default useStore;
