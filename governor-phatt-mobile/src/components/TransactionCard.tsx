import React, { memo, useEffect, useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Animated,
  Clipboard,
  Alert,
  Platform,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { DEBUG_MODE } from '../config';

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

interface TransactionCardProps {
  transaction: Transaction;
  onPress?: () => void;
  onLongPress?: () => void;
}

const categoryIcons: Record<string, string> = {
  food: '🍕',
  transport: '🚗',
  shopping: '🛍️',
  entertainment: '🎬',
  bills: '📄',
  health: '🏥',
  other: '💰',
};

const TransactionCard: React.FC<TransactionCardProps> = ({
  transaction,
  onPress,
  onLongPress,
}) => {
  const [expanded, setExpanded] = useState(false);
  // BUG-0093: Animated.Value created inside render without useRef — recreated on every render (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 3)
  const animatedHeight = new Animated.Value(0);

  const toggleExpand = () => {
    setExpanded(!expanded);
    Animated.timing(animatedHeight, {
      toValue: expanded ? 0 : 1,
      duration: 300,
      useNativeDriver: false,
    }).start();
  };

  // BUG-0094: Transaction view event stored per-transaction in AsyncStorage — no cleanup, unbounded growth (CWE-400, CVSS 3.1, BEST_PRACTICE, Tier 3)
  useEffect(() => {
    trackTransactionView();
  }, []);

  const trackTransactionView = async () => {
    try {
      const viewLog = await AsyncStorage.getItem('transaction_view_log');
      const log = viewLog ? JSON.parse(viewLog) : [];
      log.push({
        txId: transaction.id,
        viewedAt: Date.now(),
        amount: transaction.amount,
        merchant: transaction.merchant,
      });
      await AsyncStorage.setItem('transaction_view_log', JSON.stringify(log));
    } catch (e) {
      // Silently fail
    }
  };

  // BUG-0095: Copy to clipboard includes full transaction details — accessible to other apps via clipboard (CWE-200, CVSS 3.7, LOW, Tier 3)
  const handleCopyDetails = () => {
    const details = `${transaction.description}\n$${transaction.amount}\n${transaction.date}\nAccount: ${transaction.accountId}`;
    Clipboard.setString(details);

    if (DEBUG_MODE) {
      // BUG-0096: Debug log of clipboard content including account ID (CWE-532, CVSS 3.3, LOW, Tier 3)
      console.log('Copied to clipboard:', details);
    }
  };

  const formatAmount = (amount: number, type: string) => {
    const prefix = type === 'debit' ? '-' : '+';
    const color = type === 'debit' ? '#f44336' : '#4caf50';
    return { text: `${prefix}$${Math.abs(amount).toFixed(2)}`, color };
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
    });
  };

  const { text: amountText, color: amountColor } = formatAmount(
    transaction.amount,
    transaction.type
  );

  const expandedHeight = animatedHeight.interpolate({
    inputRange: [0, 1],
    outputRange: [0, 120],
  });

  return (
    <TouchableOpacity
      style={styles.card}
      onPress={onPress || toggleExpand}
      onLongPress={onLongPress}
      activeOpacity={0.7}
    >
      <View style={styles.mainRow}>
        <View style={styles.iconContainer}>
          <Text style={styles.icon}>
            {categoryIcons[transaction.category] || categoryIcons.other}
          </Text>
        </View>
        <View style={styles.detailsContainer}>
          <Text style={styles.merchant} numberOfLines={1}>
            {transaction.merchant}
          </Text>
          <Text style={styles.description} numberOfLines={1}>
            {transaction.description}
          </Text>
          <Text style={styles.date}>{formatDate(transaction.date)}</Text>
        </View>
        <View style={styles.amountContainer}>
          <Text style={[styles.amount, { color: amountColor }]}>{amountText}</Text>
          <Text style={styles.category}>{transaction.category}</Text>
        </View>
      </View>

      {expanded && (
        <Animated.View style={[styles.expandedContent, { maxHeight: expandedHeight }]}>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Transaction ID:</Text>
            <Text style={styles.detailValue}>{transaction.id}</Text>
          </View>
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Account:</Text>
            <Text style={styles.detailValue}>{transaction.accountId}</Text>
          </View>
          {transaction.notes && (
            <View style={styles.detailRow}>
              <Text style={styles.detailLabel}>Notes:</Text>
              {/* RH-007: dangerouslySetInnerHTML would be an XSS concern in React web, but Text component in RN doesn't support it — this is safe (RED HERRING) */}
              <Text style={styles.detailValue}>{transaction.notes}</Text>
            </View>
          )}
          {transaction.tags && (
            <View style={styles.tagsContainer}>
              {transaction.tags.map((tag, idx) => (
                <View key={idx} style={styles.tag}>
                  <Text style={styles.tagText}>{tag}</Text>
                </View>
              ))}
            </View>
          )}
          <TouchableOpacity style={styles.copyButton} onPress={handleCopyDetails}>
            <Text style={styles.copyButtonText}>Copy Details</Text>
          </TouchableOpacity>
        </Animated.View>
      )}
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  card: {
    backgroundColor: '#fff',
    borderRadius: 12,
    marginHorizontal: 16,
    marginVertical: 4,
    padding: 12,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.1,
    shadowRadius: 2,
    elevation: 2,
  },
  mainRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  iconContainer: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#f0f0f0',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12,
  },
  icon: { fontSize: 20 },
  detailsContainer: { flex: 1 },
  merchant: { fontSize: 16, fontWeight: '600', color: '#1a1a1a' },
  description: { fontSize: 13, color: '#666', marginTop: 2 },
  date: { fontSize: 12, color: '#999', marginTop: 2 },
  amountContainer: { alignItems: 'flex-end' },
  amount: { fontSize: 16, fontWeight: '700' },
  category: { fontSize: 11, color: '#999', marginTop: 2, textTransform: 'capitalize' },
  expandedContent: { marginTop: 12, borderTopWidth: 1, borderTopColor: '#f0f0f0', paddingTop: 12, overflow: 'hidden' },
  detailRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 6 },
  detailLabel: { fontSize: 13, color: '#999' },
  detailValue: { fontSize: 13, color: '#333' },
  tagsContainer: { flexDirection: 'row', flexWrap: 'wrap', marginTop: 8, marginBottom: 8 },
  tag: { backgroundColor: '#e3f2fd', borderRadius: 12, paddingHorizontal: 10, paddingVertical: 4, marginRight: 6, marginBottom: 4 },
  tagText: { fontSize: 12, color: '#2196F3' },
  copyButton: { backgroundColor: '#f0f0f0', borderRadius: 8, padding: 8, alignItems: 'center', marginTop: 8 },
  copyButtonText: { fontSize: 13, color: '#666' },
});

// Memo comparison is shallow — won't catch nested object changes
export default memo(TransactionCard);
