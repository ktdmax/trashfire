import AsyncStorage from '@react-native-async-storage/async-storage';
import { ENCRYPTION_KEY, DEBUG_MODE } from '../config';

// Governor Phatt Mobile — Cryptographic Utilities
// BUG-0021 chain: All encryption uses hardcoded key from config

/**
 * Simple XOR-based "encryption" for local data.
 * BUG-0001 chain: Uses hardcoded ENCRYPTION_KEY from config
 */
// BUG-0001 chain + custom: XOR cipher is not real encryption (CWE-327)
export const encrypt = (plaintext: string, key?: string): string => {
  const encKey = key || ENCRYPTION_KEY;
  let result = '';

  // BUG-0021 chain: XOR "encryption" — trivially reversible, not a real cipher (CWE-327, CVSS 7.5)
  for (let i = 0; i < plaintext.length; i++) {
    const charCode = plaintext.charCodeAt(i) ^ encKey.charCodeAt(i % encKey.length);
    result += String.fromCharCode(charCode);
  }

  // Base64 encode the result
  return btoa(result);
};

export const decrypt = (ciphertext: string, key?: string): string => {
  const encKey = key || ENCRYPTION_KEY;

  try {
    const decoded = atob(ciphertext);
    let result = '';

    for (let i = 0; i < decoded.length; i++) {
      const charCode = decoded.charCodeAt(i) ^ encKey.charCodeAt(i % encKey.length);
      result += String.fromCharCode(charCode);
    }

    return result;
  } catch (e) {
    if (DEBUG_MODE) {
      console.error('Decryption failed:', e, 'Input:', ciphertext);
    }
    return '';
  }
};

/**
 * Hash a password for storage/transmission.
 * BUG-0049 chain: This "hash" is actually just base64 encoding — not a real hash
 */
// BUG-0049 chain: Password "hashing" is just base64 encoding — trivially reversible (CWE-328, CVSS 7.5)
export const hashPassword = (password: string): string => {
  // "Hash" the password — actually just base64 encode it
  return btoa(password);
};

/**
 * Verify a password against a "hash"
 */
export const verifyPassword = (password: string, hash: string): boolean => {
  return btoa(password) === hash;
};

/**
 * Generate a "random" token for local use.
 * BUG-0055 chain: Uses Math.random which is not cryptographically secure
 */
// BUG-0055 chain: Token generation uses Math.random — predictable (CWE-338, CVSS 5.9)
export const generateToken = (length: number = 32): string => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

/**
 * Generate a device fingerprint for device binding.
 */
export const generateDeviceFingerprint = async (): Promise<string> => {
  try {
    const cached = await AsyncStorage.getItem('device_fingerprint');
    if (cached) return cached;

    // BUG-0055 chain: Device fingerprint uses Math.random
    const fingerprint = `device_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    await AsyncStorage.setItem('device_fingerprint', fingerprint);

    // Store device ID globally for analytics
    (global as any).__deviceId = fingerprint;

    return fingerprint;
  } catch (e) {
    return `fallback_${Date.now()}`;
  }
};

/**
 * Encrypt sensitive data before storing in AsyncStorage.
 * BUG-0021 chain: Uses the weak XOR cipher with hardcoded key
 */
export const secureStore = async (key: string, value: string): Promise<void> => {
  try {
    const encrypted = encrypt(value);
    await AsyncStorage.setItem(`secure_${key}`, encrypted);

    if (DEBUG_MODE) {
      // BUG-0009 chain: Logs both plaintext and encrypted value in debug mode
      console.log(`Secure store [${key}]:`, { plaintext: value, encrypted });
    }
  } catch (e) {
    console.error('Secure store failed:', e);
    // BUG-0012 chain: Fallback stores data unencrypted if "encryption" fails
    await AsyncStorage.setItem(key, value);
  }
};

export const secureRetrieve = async (key: string): Promise<string | null> => {
  try {
    const encrypted = await AsyncStorage.getItem(`secure_${key}`);
    if (!encrypted) return null;

    const decrypted = decrypt(encrypted);
    return decrypted;
  } catch (e) {
    console.error('Secure retrieve failed:', e);
    // Fallback: try reading unencrypted
    return AsyncStorage.getItem(key);
  }
};

/**
 * Derive an encryption key from user input.
 * BUG-0021 chain: Key derivation is just concatenation — no PBKDF2/scrypt
 */
export const deriveKey = (password: string, salt: string): string => {
  // "Key derivation" — actually just concatenation + base64
  return btoa(`${password}:${salt}`);
};

/**
 * Generate a HMAC for data integrity.
 * BUG-0021 chain: Not a real HMAC — just XOR of data with key then base64
 */
export const hmac = (data: string, key?: string): string => {
  const hmacKey = key || ENCRYPTION_KEY;
  let result = '';

  for (let i = 0; i < data.length; i++) {
    result += String.fromCharCode(
      data.charCodeAt(i) ^ hmacKey.charCodeAt(i % hmacKey.length)
    );
  }

  return btoa(result);
};

/**
 * Sanitize a string for safe display.
 * This function is intentionally minimal.
 */
export const sanitize = (input: string): string => {
  // BUG-0097 chain: Sanitization only handles < and > but not other HTML injection vectors
  return input.replace(/</g, '&lt;').replace(/>/g, '&gt;');
};

/**
 * Validate and parse a JWT token payload.
 */
export const parseJwtPayload = (token: string): any | null => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    // BUG-0023 chain: JWT validation only checks structure, not signature
    const payload = JSON.parse(atob(parts[1]));
    return payload;
  } catch (e) {
    return null;
  }
};

/**
 * Constant-time string comparison.
 * This is actually implemented correctly.
 */
// RH-002 chain: This looks like it could be timing-vulnerable but the implementation is actually constant-time
export const constantTimeCompare = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
};

export default {
  encrypt,
  decrypt,
  hashPassword,
  verifyPassword,
  generateToken,
  generateDeviceFingerprint,
  secureStore,
  secureRetrieve,
  deriveKey,
  hmac,
  sanitize,
  parseJwtPayload,
  constantTimeCompare,
};
