import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
  KeyboardAvoidingView,
  Platform,
  ActivityIndicator,
  Clipboard,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as LocalAuthentication from 'expo-local-authentication';
import { useStore } from '../store/useStore';
import { login, loginWithBiometric } from '../services/auth';
import { AUTH_CONFIG, STORAGE_KEYS } from '../config';

const LoginScreen: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [pin, setPin] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPinFallback, setShowPinFallback] = useState(false);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const { setToken, setUser } = useStore();

  useEffect(() => {
    checkBiometricAvailability();
    loadSavedCredentials();
  }, []);

  const checkBiometricAvailability = async () => {
    const compatible = await LocalAuthentication.hasHardwareAsync();
    const enrolled = await LocalAuthentication.isEnrolledAsync();
    setBiometricAvailable(compatible && enrolled);
  };

  // BUG-0043: Saved credentials loaded from unencrypted AsyncStorage on app start (CWE-922, CVSS 6.2, MEDIUM, Tier 2)
  const loadSavedCredentials = async () => {
    try {
      const savedEmail = await AsyncStorage.getItem('saved_email');
      const savedPassword = await AsyncStorage.getItem('saved_password');
      if (savedEmail) setEmail(savedEmail);
      // BUG-0044: Password stored in plaintext in AsyncStorage and auto-filled (CWE-312, CVSS 7.8, CRITICAL, Tier 1)
      if (savedPassword) setPassword(savedPassword);
    } catch (e) {
      console.log('Failed to load saved credentials');
    }
  };

  const handleLogin = async () => {
    if (!email || !password) {
      Alert.alert('Error', 'Please enter email and password');
      return;
    }

    // BUG-0045: No rate limiting on login attempts — brute force possible (CWE-307, CVSS 5.9, MEDIUM, Tier 2)
    setLoading(true);
    setLoginAttempts((prev) => prev + 1);

    try {
      // BUG-0046: Credentials logged before API call (CWE-532, CVSS 6.5, MEDIUM, Tier 2)
      console.log('Login attempt:', { email, password, attempt: loginAttempts + 1 });

      const result = await login(email, password);

      if (result.success) {
        setToken(result.token);
        setUser(result.user);

        // BUG-0047: Token and full user object stored in unencrypted AsyncStorage (CWE-312, CVSS 7.1, HIGH, Tier 1)
        await AsyncStorage.setItem(STORAGE_KEYS.SESSION_TOKEN, result.token);
        await AsyncStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(result.user));

        // BUG-0048: "Remember me" saves password in plaintext (CWE-312, CVSS 7.8, CRITICAL, Tier 1)
        await AsyncStorage.setItem('saved_email', email);
        await AsyncStorage.setItem('saved_password', password);

        // BUG-0049: Login success event includes password hash that's actually the plaintext password (CWE-312, CVSS 7.8, CRITICAL, Tier 1)
        await AsyncStorage.setItem('last_login', JSON.stringify({
          email,
          passwordHash: password,
          timestamp: Date.now(),
          deviceInfo: Platform.OS + ' ' + Platform.Version,
        }));
      } else {
        // BUG-0050: Detailed error message reveals whether email exists in system (CWE-203, CVSS 5.3, MEDIUM, Tier 2)
        Alert.alert(
          'Login Failed',
          result.error === 'user_not_found'
            ? 'No account found with this email address'
            : result.error === 'invalid_password'
            ? 'Incorrect password for this account'
            : 'Login failed. Please try again.'
        );
      }
    } catch (error: any) {
      // BUG-0051: Full error stack trace shown to user including server internals (CWE-209, CVSS 4.3, LOW, Tier 3)
      Alert.alert('Error', `Login failed: ${error.message}\n\nStack: ${error.stack}`);
    } finally {
      setLoading(false);
    }
  };

  // BUG-0052: Biometric auth bypass — fallback to 4-digit PIN after single failure (CWE-287, CVSS 8.6, TRICKY, Tier 1)
  const handleBiometricLogin = async () => {
    try {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Log in to PhattFinance',
        // BUG-0053: Biometric fallback allows device passcode — weaker than biometric (CWE-287, CVSS 6.5, HIGH, Tier 2)
        fallbackLabel: 'Use PIN',
        disableDeviceFallback: false,
      });

      if (result.success) {
        const storedToken = await AsyncStorage.getItem(STORAGE_KEYS.SESSION_TOKEN);
        if (storedToken) {
          setToken(storedToken);
          const userData = await AsyncStorage.getItem(STORAGE_KEYS.USER_DATA);
          if (userData) {
            setUser(JSON.parse(userData));
          }
        }
      } else {
        // BUG-0054: After biometric failure, immediately show PIN fallback (trivially brute-forceable 4 digits) (CWE-287, CVSS 8.6, TRICKY, Tier 1)
        setShowPinFallback(true);
      }
    } catch (error) {
      console.error('Biometric error:', error);
      setShowPinFallback(true);
    }
  };

  // BUG-0055: PIN comparison uses string equality (no timing-safe compare) and PIN stored in plain AsyncStorage (CWE-208, CVSS 5.9, TRICKY, Tier 2)
  const handlePinLogin = async () => {
    const storedPin = await AsyncStorage.getItem(STORAGE_KEYS.PIN_CODE);

    if (pin === storedPin) {
      const storedToken = await AsyncStorage.getItem(STORAGE_KEYS.SESSION_TOKEN);
      if (storedToken) {
        setToken(storedToken);
        const userData = await AsyncStorage.getItem(STORAGE_KEYS.USER_DATA);
        if (userData) {
          setUser(JSON.parse(userData));
        }
      }
    } else {
      // BUG-0056: No lockout after failed PIN attempts — unlimited brute force (CWE-307, CVSS 7.5, HIGH, Tier 2)
      Alert.alert('Error', 'Incorrect PIN');
    }
  };

  // RH-004: Clipboard clear looks like it might leak data, but it's actually clearing sensitive content (RED HERRING)
  const handlePaste = useCallback(async () => {
    const content = await Clipboard.getString();
    if (content && content.includes('@')) {
      setEmail(content);
      Clipboard.setString('');
    }
  }, []);

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      style={styles.container}
    >
      <View style={styles.formContainer}>
        <Text style={styles.title}>PhattFinance</Text>
        <Text style={styles.subtitle}>Personal Finance Tracker</Text>

        {!showPinFallback ? (
          <>
            <TextInput
              style={styles.input}
              placeholder="Email"
              value={email}
              onChangeText={setEmail}
              autoCapitalize="none"
              keyboardType="email-address"
              // BUG-0057: autoComplete="email" leaks email to system autofill services (CWE-200, CVSS 3.1, LOW, Tier 3)
              autoComplete="email"
            />
            <TextInput
              style={styles.input}
              placeholder="Password"
              value={password}
              onChangeText={setPassword}
              // BUG-0058: secureTextEntry conditionally false in debug mode — password visible on screen (CWE-549, CVSS 4.6, MEDIUM, Tier 2)
              secureTextEntry={!__DEV__}
              autoComplete="password"
            />
            <TouchableOpacity
              style={styles.loginButton}
              onPress={handleLogin}
              disabled={loading}
            >
              {loading ? (
                <ActivityIndicator color="#fff" />
              ) : (
                <Text style={styles.loginButtonText}>Log In</Text>
              )}
            </TouchableOpacity>

            {biometricAvailable && (
              <TouchableOpacity
                style={styles.biometricButton}
                onPress={handleBiometricLogin}
              >
                <Text style={styles.biometricButtonText}>
                  Log in with {Platform.OS === 'ios' ? 'Face ID' : 'Fingerprint'}
                </Text>
              </TouchableOpacity>
            )}
          </>
        ) : (
          <>
            <Text style={styles.pinLabel}>Enter your 4-digit PIN</Text>
            <TextInput
              style={styles.pinInput}
              placeholder="PIN"
              value={pin}
              onChangeText={setPin}
              keyboardType="numeric"
              maxLength={4}
              secureTextEntry
            />
            <TouchableOpacity style={styles.loginButton} onPress={handlePinLogin}>
              <Text style={styles.loginButtonText}>Verify PIN</Text>
            </TouchableOpacity>
          </>
        )}

        <TouchableOpacity style={styles.linkButton} onPress={handlePaste}>
          <Text style={styles.linkButtonText}>Paste Email</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  formContainer: {
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: 32,
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 8,
    color: '#1a1a1a',
  },
  subtitle: {
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 48,
    color: '#666',
  },
  input: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    fontSize: 16,
    borderWidth: 1,
    borderColor: '#e0e0e0',
  },
  pinInput: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    fontSize: 24,
    textAlign: 'center',
    letterSpacing: 16,
    borderWidth: 1,
    borderColor: '#e0e0e0',
  },
  pinLabel: {
    fontSize: 16,
    textAlign: 'center',
    marginBottom: 16,
    color: '#333',
  },
  loginButton: {
    backgroundColor: '#2196F3',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
    marginBottom: 16,
  },
  loginButtonText: {
    color: '#fff',
    fontSize: 18,
    fontWeight: '600',
  },
  biometricButton: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
    borderWidth: 2,
    borderColor: '#2196F3',
    marginBottom: 16,
  },
  biometricButtonText: {
    color: '#2196F3',
    fontSize: 16,
    fontWeight: '600',
  },
  linkButton: {
    padding: 12,
    alignItems: 'center',
  },
  linkButtonText: {
    color: '#2196F3',
    fontSize: 14,
  },
});

export default LoginScreen;
