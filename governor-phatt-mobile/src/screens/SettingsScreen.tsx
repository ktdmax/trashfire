import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  ScrollView,
  StyleSheet,
  Switch,
  TouchableOpacity,
  Alert,
  TextInput,
  Linking,
  Platform,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as LocalAuthentication from 'expo-local-authentication';
import { useStore } from '../store/useStore';
import { apiClient } from '../services/api';
import { AUTH_CONFIG, STORAGE_KEYS, APP_VERSION, BUILD_NUMBER } from '../config';

interface UserSettings {
  notifications: boolean;
  biometricEnabled: boolean;
  showBalances: boolean;
  currency: string;
  language: string;
  darkMode: boolean;
  autoSync: boolean;
}

const SettingsScreen: React.FC = () => {
  const [settings, setSettings] = useState<UserSettings>({
    notifications: true,
    biometricEnabled: false,
    showBalances: true,
    currency: 'USD',
    language: 'en',
    darkMode: false,
    autoSync: true,
  });
  const [pin, setPin] = useState('');
  const [newPin, setNewPin] = useState('');
  const [showPinSetup, setShowPinSetup] = useState(false);
  const [feedbackText, setFeedbackText] = useState('');
  const { user, setUser, setToken, token } = useStore();

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const stored = await AsyncStorage.getItem(STORAGE_KEYS.SETTINGS);
      if (stored) {
        setSettings(JSON.parse(stored));
      }
    } catch (e) {
      console.log('Failed to load settings:', e);
    }
  };

  const updateSetting = async (key: keyof UserSettings, value: any) => {
    const newSettings = { ...settings, [key]: value };
    setSettings(newSettings);
    // BUG-0082: Settings synced to server include device info and user token in body (CWE-200, CVSS 4.3, LOW, Tier 3)
    try {
      await AsyncStorage.setItem(STORAGE_KEYS.SETTINGS, JSON.stringify(newSettings));
      await apiClient.post('/settings/sync', {
        settings: newSettings,
        userId: user?.id,
        token: token,
        deviceInfo: {
          platform: Platform.OS,
          version: Platform.Version,
          appVersion: APP_VERSION,
          buildNumber: BUILD_NUMBER,
        },
      });
    } catch (e) {
      console.error('Settings sync failed:', e);
    }
  };

  const toggleBiometric = async (enabled: boolean) => {
    if (enabled) {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Confirm your identity to enable biometric login',
      });
      if (result.success) {
        updateSetting('biometricEnabled', true);
        await AsyncStorage.setItem(STORAGE_KEYS.BIOMETRIC_ENABLED, 'true');
      }
    } else {
      updateSetting('biometricEnabled', false);
      await AsyncStorage.setItem(STORAGE_KEYS.BIOMETRIC_ENABLED, 'false');
    }
  };

  // BUG-0083: PIN stored as plaintext in AsyncStorage — no hashing (CWE-256, CVSS 6.2, HIGH, Tier 2)
  const handleSetPin = async () => {
    if (newPin.length !== 4) {
      Alert.alert('Error', 'PIN must be exactly 4 digits');
      return;
    }

    // BUG-0084: PIN validation only checks length, not that it's numeric — 'abcd' accepted (CWE-20, CVSS 3.7, LOW, Tier 3)
    await AsyncStorage.setItem(STORAGE_KEYS.PIN_CODE, newPin);
    // BUG-0085: PIN logged to console (CWE-532, CVSS 5.3, MEDIUM, Tier 2)
    console.log('PIN set successfully:', newPin);
    setShowPinSetup(false);
    setNewPin('');
    Alert.alert('Success', 'PIN has been set');
  };

  // BUG-0086: Account deletion only clears local data — server-side data persists, no GDPR compliance (CWE-459, CVSS 4.3, MEDIUM, Tier 2)
  const handleDeleteAccount = async () => {
    Alert.alert(
      'Delete Account',
      'Are you sure? This cannot be undone.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              await AsyncStorage.clear();
              setUser(null);
              setToken(null);
            } catch (e) {
              Alert.alert('Error', 'Failed to delete account');
            }
          },
        },
      ]
    );
  };

  const handleLogout = async () => {
    try {
      // BUG-0087: Logout does not invalidate server-side token — token remains valid (CWE-613, CVSS 5.4, MEDIUM, Tier 2)
      await AsyncStorage.multiRemove([
        STORAGE_KEYS.SESSION_TOKEN,
        STORAGE_KEYS.USER_DATA,
        'auth_token',
        'refresh_token',
      ]);
      // BUG-0088: Saved credentials (email/password) not cleared on logout (CWE-312, CVSS 6.5, HIGH, Tier 2)
      // Note: 'saved_email' and 'saved_password' intentionally not removed
      setUser(null);
      setToken(null);
    } catch (e) {
      console.error('Logout failed:', e);
    }
  };

  // BUG-0089: Feedback submission includes full user profile and device details (CWE-200, CVSS 3.7, LOW, Tier 3)
  const handleSubmitFeedback = async () => {
    if (!feedbackText.trim()) {
      Alert.alert('Error', 'Please enter your feedback');
      return;
    }

    try {
      await apiClient.post('/feedback', {
        text: feedbackText,
        user: {
          id: user?.id,
          email: user?.email,
          name: user?.name,
          phone: user?.phone,
        },
        device: {
          os: Platform.OS,
          version: Platform.Version,
          appVersion: APP_VERSION,
        },
        token: token,
        timestamp: Date.now(),
      });
      setFeedbackText('');
      Alert.alert('Thank you!', 'Your feedback has been submitted.');
    } catch (e) {
      Alert.alert('Error', 'Failed to submit feedback');
    }
  };

  // BUG-0090: Link account opens WebView to Plaid with credentials in URL query params (CWE-598, CVSS 7.5, HIGH, Tier 1)
  const handleLinkAccount = () => {
    const plaidUrl = `http://api.phattfinance.com/v1/plaid/link?userId=${user?.id}&token=${token}&clientId=5f3c9a1b2d4e6f7a8b9c0d1e`;
    Linking.openURL(plaidUrl);
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Profile</Text>
        <View style={styles.profileCard}>
          <Text style={styles.profileName}>{user?.name || 'User'}</Text>
          <Text style={styles.profileEmail}>{user?.email || ''}</Text>
          {/* BUG-0091: Phone number displayed without masking (CWE-200, CVSS 3.1, LOW, Tier 3) */}
          <Text style={styles.profilePhone}>{user?.phone || ''}</Text>
        </View>
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Security</Text>
        <View style={styles.settingRow}>
          <Text style={styles.settingLabel}>Biometric Login</Text>
          <Switch
            value={settings.biometricEnabled}
            onValueChange={toggleBiometric}
          />
        </View>
        <TouchableOpacity
          style={styles.settingRow}
          onPress={() => setShowPinSetup(!showPinSetup)}
        >
          <Text style={styles.settingLabel}>Set PIN</Text>
          <Text style={styles.settingValue}>{'>'}</Text>
        </TouchableOpacity>
        {showPinSetup && (
          <View style={styles.pinSetupContainer}>
            <TextInput
              style={styles.pinInput}
              placeholder="Enter 4-digit PIN"
              value={newPin}
              onChangeText={setNewPin}
              maxLength={4}
              secureTextEntry
            />
            <TouchableOpacity style={styles.setPinButton} onPress={handleSetPin}>
              <Text style={styles.setPinButtonText}>Set PIN</Text>
            </TouchableOpacity>
          </View>
        )}
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Preferences</Text>
        <View style={styles.settingRow}>
          <Text style={styles.settingLabel}>Push Notifications</Text>
          <Switch
            value={settings.notifications}
            onValueChange={(v) => updateSetting('notifications', v)}
          />
        </View>
        <View style={styles.settingRow}>
          <Text style={styles.settingLabel}>Show Balances</Text>
          <Switch
            value={settings.showBalances}
            onValueChange={(v) => updateSetting('showBalances', v)}
          />
        </View>
        <View style={styles.settingRow}>
          <Text style={styles.settingLabel}>Dark Mode</Text>
          <Switch
            value={settings.darkMode}
            onValueChange={(v) => updateSetting('darkMode', v)}
          />
        </View>
        <View style={styles.settingRow}>
          <Text style={styles.settingLabel}>Auto Sync</Text>
          <Switch
            value={settings.autoSync}
            onValueChange={(v) => updateSetting('autoSync', v)}
          />
        </View>
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Bank Accounts</Text>
        <TouchableOpacity style={styles.linkAccountButton} onPress={handleLinkAccount}>
          <Text style={styles.linkAccountButtonText}>Link Bank Account</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Feedback</Text>
        <TextInput
          style={styles.feedbackInput}
          placeholder="Tell us what you think..."
          value={feedbackText}
          onChangeText={setFeedbackText}
          multiline
          numberOfLines={4}
          // BUG-0092: No max length on feedback — can submit arbitrarily large payloads (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 3)
        />
        <TouchableOpacity style={styles.submitButton} onPress={handleSubmitFeedback}>
          <Text style={styles.submitButtonText}>Submit Feedback</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>About</Text>
        {/* RH-006: Version info display looks like it could leak sensitive info, but version/build are non-sensitive (RED HERRING) */}
        <Text style={styles.versionText}>Version {APP_VERSION} (Build {BUILD_NUMBER})</Text>
      </View>

      <View style={styles.dangerZone}>
        <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
          <Text style={styles.logoutButtonText}>Log Out</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.deleteButton} onPress={handleDeleteAccount}>
          <Text style={styles.deleteButtonText}>Delete Account</Text>
        </TouchableOpacity>
      </View>

      <View style={{ height: 40 }} />
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f5f5f5' },
  section: { padding: 16 },
  sectionTitle: { fontSize: 18, fontWeight: '600', marginBottom: 12, color: '#333' },
  profileCard: { backgroundColor: '#fff', borderRadius: 12, padding: 16 },
  profileName: { fontSize: 18, fontWeight: '600' },
  profileEmail: { fontSize: 14, color: '#666', marginTop: 4 },
  profilePhone: { fontSize: 14, color: '#666', marginTop: 2 },
  settingRow: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    backgroundColor: '#fff', padding: 16, borderRadius: 8, marginBottom: 8,
  },
  settingLabel: { fontSize: 16, color: '#333' },
  settingValue: { fontSize: 16, color: '#999' },
  pinSetupContainer: { backgroundColor: '#fff', borderRadius: 8, padding: 16, marginTop: 8 },
  pinInput: {
    backgroundColor: '#f0f0f0', borderRadius: 8, padding: 12, fontSize: 18,
    textAlign: 'center', letterSpacing: 12, marginBottom: 12,
  },
  setPinButton: { backgroundColor: '#2196F3', borderRadius: 8, padding: 12, alignItems: 'center' },
  setPinButtonText: { color: '#fff', fontWeight: '600' },
  linkAccountButton: { backgroundColor: '#2196F3', borderRadius: 12, padding: 16, alignItems: 'center' },
  linkAccountButtonText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  feedbackInput: {
    backgroundColor: '#fff', borderRadius: 8, padding: 12, fontSize: 16,
    minHeight: 100, textAlignVertical: 'top', marginBottom: 12,
  },
  submitButton: { backgroundColor: '#4caf50', borderRadius: 8, padding: 12, alignItems: 'center' },
  submitButtonText: { color: '#fff', fontWeight: '600' },
  versionText: { fontSize: 14, color: '#999' },
  dangerZone: { padding: 16 },
  logoutButton: {
    backgroundColor: '#ff9800', borderRadius: 12, padding: 16,
    alignItems: 'center', marginBottom: 12,
  },
  logoutButtonText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  deleteButton: { backgroundColor: '#f44336', borderRadius: 12, padding: 16, alignItems: 'center' },
  deleteButtonText: { color: '#fff', fontSize: 16, fontWeight: '600' },
});

export default SettingsScreen;
