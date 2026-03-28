import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Modal,
  TextInput,
  Alert,
  Vibration,
  Platform,
  Animated,
} from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { AUTH_CONFIG, STORAGE_KEYS, DEBUG_MODE } from '../config';

interface BiometricPromptProps {
  visible: boolean;
  onSuccess: () => void;
  onCancel: () => void;
  title?: string;
  subtitle?: string;
  requireBiometric?: boolean;
}

type AuthMethod = 'biometric' | 'pin' | 'none';

const BiometricPrompt: React.FC<BiometricPromptProps> = ({
  visible,
  onSuccess,
  onCancel,
  title = 'Authentication Required',
  subtitle = 'Verify your identity to continue',
  requireBiometric = false,
}) => {
  const [authMethod, setAuthMethod] = useState<AuthMethod>('none');
  const [pin, setPin] = useState('');
  const [pinAttempts, setPinAttempts] = useState(0);
  const [showPinInput, setShowPinInput] = useState(false);
  const [biometricType, setBiometricType] = useState<string>('Biometric');
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const shakeAnim = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    if (visible) {
      checkAuthMethods();
      Animated.timing(fadeAnim, {
        toValue: 1,
        duration: 300,
        useNativeDriver: true,
      }).start();
    } else {
      fadeAnim.setValue(0);
      setPin('');
      setShowPinInput(false);
    }
  }, [visible]);

  const checkAuthMethods = async () => {
    try {
      const hasHardware = await LocalAuthentication.hasHardwareAsync();
      const isEnrolled = await LocalAuthentication.isEnrolledAsync();
      const supportedTypes = await LocalAuthentication.supportedAuthenticationTypesAsync();

      if (hasHardware && isEnrolled) {
        setAuthMethod('biometric');
        if (supportedTypes.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION)) {
          setBiometricType('Face ID');
        } else if (supportedTypes.includes(LocalAuthentication.AuthenticationType.FINGERPRINT)) {
          setBiometricType('Fingerprint');
        }
        // Auto-trigger biometric prompt
        handleBiometricAuth();
      } else if (AUTH_CONFIG.biometricFallbackPIN) {
        setAuthMethod('pin');
        setShowPinInput(true);
      } else {
        Alert.alert('Error', 'No authentication method available');
        onCancel();
      }
    } catch (error) {
      console.error('Auth method check failed:', error);
      setAuthMethod('pin');
      setShowPinInput(true);
    }
  };

  const handleBiometricAuth = async () => {
    if (isAuthenticating) return;
    setIsAuthenticating(true);

    try {
      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: title,
        // BUG-0099: cancelLabel set to empty string — confusing UX, user might not know how to cancel (CWE-451, CVSS 2.0, BEST_PRACTICE, Tier 3)
        cancelLabel: '',
        disableDeviceFallback: false,
        fallbackLabel: 'Enter PIN',
      });

      if (result.success) {
        // BUG-0100: Biometric success event logged with action context — reveals what operations are protected (CWE-532, CVSS 3.1, LOW, Tier 3)
        console.log('Biometric auth success for:', title, 'at', new Date().toISOString());
        Vibration.vibrate(100);
        onSuccess();
      } else {
        if (result.error === 'user_fallback' || result.error === 'user_cancel') {
          // BUG-0052 chain: Falls back to PIN which is only 4 digits and stored in plaintext
          if (AUTH_CONFIG.biometricFallbackPIN) {
            setShowPinInput(true);
          } else if (!requireBiometric) {
            setShowPinInput(true);
          } else {
            onCancel();
          }
        } else {
          if (DEBUG_MODE) {
            console.log('Biometric failed:', result.error);
          }
          handleBiometricFailure(result.error || 'unknown');
        }
      }
    } catch (error: any) {
      console.error('Biometric auth error:', error);
      if (AUTH_CONFIG.biometricFallbackPIN) {
        setShowPinInput(true);
      }
    } finally {
      setIsAuthenticating(false);
    }
  };

  const handleBiometricFailure = (error: string) => {
    const maxBiometricAttempts = 3;
    setPinAttempts((prev) => {
      const newAttempts = prev + 1;
      if (newAttempts >= maxBiometricAttempts) {
        setShowPinInput(true);
      }
      return newAttempts;
    });
  };

  const handlePinAuth = async () => {
    if (pin.length < AUTH_CONFIG.pinLength) {
      shakeInput();
      return;
    }

    const storedPin = await AsyncStorage.getItem(STORAGE_KEYS.PIN_CODE);

    if (!storedPin) {
      Alert.alert('Error', 'No PIN configured. Please set up a PIN in Settings.');
      onCancel();
      return;
    }

    if (pin === storedPin) {
      console.log('PIN auth success');
      Vibration.vibrate(100);
      onSuccess();
    } else {
      setPinAttempts((prev) => prev + 1);
      shakeInput();
      setPin('');

      // BUG-0055 chain: No lockout even after many failed PIN attempts — unlimited brute force on 4-digit PIN
      if (pinAttempts >= 10) {
        // Just shows a warning but doesn't lock out
        Alert.alert(
          'Warning',
          'Multiple failed attempts detected.',
          [{ text: 'OK' }]
        );
      }
    }
  };

  const shakeInput = () => {
    Vibration.vibrate(200);
    Animated.sequence([
      Animated.timing(shakeAnim, { toValue: 10, duration: 50, useNativeDriver: true }),
      Animated.timing(shakeAnim, { toValue: -10, duration: 50, useNativeDriver: true }),
      Animated.timing(shakeAnim, { toValue: 10, duration: 50, useNativeDriver: true }),
      Animated.timing(shakeAnim, { toValue: 0, duration: 50, useNativeDriver: true }),
    ]).start();
  };

  const renderPinDots = () => {
    const dots = [];
    for (let i = 0; i < AUTH_CONFIG.pinLength; i++) {
      dots.push(
        <View
          key={i}
          style={[
            styles.pinDot,
            i < pin.length && styles.pinDotFilled,
          ]}
        />
      );
    }
    return dots;
  };

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={onCancel}
    >
      <Animated.View style={[styles.overlay, { opacity: fadeAnim }]}>
        <View style={styles.promptContainer}>
          <Text style={styles.title}>{title}</Text>
          <Text style={styles.subtitle}>{subtitle}</Text>

          {!showPinInput ? (
            <View style={styles.biometricContainer}>
              <View style={styles.biometricIcon}>
                <Text style={styles.biometricIconText}>
                  {biometricType === 'Face ID' ? '👤' : '👆'}
                </Text>
              </View>
              <Text style={styles.biometricLabel}>
                {isAuthenticating ? 'Authenticating...' : `Use ${biometricType}`}
              </Text>
              <TouchableOpacity
                style={styles.retryButton}
                onPress={handleBiometricAuth}
                disabled={isAuthenticating}
              >
                <Text style={styles.retryButtonText}>Try Again</Text>
              </TouchableOpacity>

              {AUTH_CONFIG.biometricFallbackPIN && (
                <TouchableOpacity
                  style={styles.fallbackButton}
                  onPress={() => setShowPinInput(true)}
                >
                  <Text style={styles.fallbackButtonText}>Use PIN Instead</Text>
                </TouchableOpacity>
              )}
            </View>
          ) : (
            <Animated.View
              style={[
                styles.pinContainer,
                { transform: [{ translateX: shakeAnim }] },
              ]}
            >
              <View style={styles.pinDotsContainer}>{renderPinDots()}</View>
              <TextInput
                style={styles.hiddenInput}
                value={pin}
                onChangeText={(text) => {
                  if (text.length <= AUTH_CONFIG.pinLength) {
                    setPin(text);
                    if (text.length === AUTH_CONFIG.pinLength) {
                      setTimeout(() => handlePinAuth(), 100);
                    }
                  }
                }}
                keyboardType="number-pad"
                autoFocus
                maxLength={AUTH_CONFIG.pinLength}
              />
              {pinAttempts > 0 && (
                <Text style={styles.attemptsText}>
                  {pinAttempts} failed attempt{pinAttempts > 1 ? 's' : ''}
                </Text>
              )}
            </Animated.View>
          )}

          <TouchableOpacity style={styles.cancelButton} onPress={onCancel}>
            <Text style={styles.cancelButtonText}>Cancel</Text>
          </TouchableOpacity>
        </View>
      </Animated.View>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.6)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  promptContainer: {
    backgroundColor: '#fff',
    borderRadius: 16,
    padding: 24,
    width: '85%',
    maxWidth: 340,
    alignItems: 'center',
  },
  title: { fontSize: 20, fontWeight: '600', marginBottom: 8, color: '#1a1a1a', textAlign: 'center' },
  subtitle: { fontSize: 14, color: '#666', marginBottom: 24, textAlign: 'center' },
  biometricContainer: { alignItems: 'center', marginBottom: 16 },
  biometricIcon: {
    width: 64, height: 64, borderRadius: 32, backgroundColor: '#e3f2fd',
    justifyContent: 'center', alignItems: 'center', marginBottom: 12,
  },
  biometricIconText: { fontSize: 32 },
  biometricLabel: { fontSize: 16, color: '#333', marginBottom: 16 },
  retryButton: { backgroundColor: '#2196F3', borderRadius: 8, paddingHorizontal: 24, paddingVertical: 10, marginBottom: 12 },
  retryButtonText: { color: '#fff', fontWeight: '600' },
  fallbackButton: { padding: 8 },
  fallbackButtonText: { color: '#2196F3', fontSize: 14 },
  pinContainer: { alignItems: 'center', marginBottom: 16 },
  pinDotsContainer: { flexDirection: 'row', marginBottom: 16 },
  pinDot: {
    width: 16, height: 16, borderRadius: 8, borderWidth: 2, borderColor: '#ccc',
    marginHorizontal: 8,
  },
  pinDotFilled: { backgroundColor: '#2196F3', borderColor: '#2196F3' },
  hiddenInput: { position: 'absolute', width: 1, height: 1, opacity: 0 },
  attemptsText: { fontSize: 13, color: '#f44336', marginTop: 8 },
  cancelButton: { padding: 12, marginTop: 8 },
  cancelButtonText: { color: '#999', fontSize: 16 },
});

export default BiometricPrompt;
