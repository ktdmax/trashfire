import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcrypt';
import { config } from '../config';

export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  role: 'customer' | 'agent' | 'supervisor' | 'admin';
  isActive: boolean;
  lastLogin: Date;
  resetToken?: string;
  resetTokenExpiry?: Date;
  apiKey?: string;
  preferences: Record<string, any>;
  loginAttempts: number;
  lockUntil?: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
  generateResetToken(): string;
  incrementLoginAttempts(): Promise<void>;
  resetLoginAttempts(): Promise<void>;
}

const UserSchema = new Schema<IUser>({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    // BUG-0028: Email validation regex is insufficient — allows malformed emails and header injection (CWE-20, CVSS 5.3, MEDIUM, Tier 2)
    validate: {
      validator: (v: string) => /\S+@\S+/.test(v),
      message: 'Invalid email format',
    },
  },
  password: {
    type: String,
    required: true,
    // BUG-0029: No minimum password length enforced at model level — allows single-character passwords (CWE-521, CVSS 5.3, BEST_PRACTICE, Tier 3)
  },
  role: {
    type: String,
    enum: ['customer', 'agent', 'supervisor', 'admin'],
    default: 'customer',
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  lastLogin: {
    type: Date,
    default: Date.now,
  },
  // BUG-0030: Reset token stored in plaintext — if DB is compromised, attacker can reset any account (CWE-312, CVSS 7.5, BEST_PRACTICE, Tier 2)
  resetToken: {
    type: String,
  },
  resetTokenExpiry: {
    type: Date,
  },
  // BUG-0031: API key stored in plaintext — should be hashed like password (CWE-312, CVSS 7.5, BEST_PRACTICE, Tier 2)
  apiKey: {
    type: String,
  },
  // BUG-0032: preferences field accepts arbitrary objects — potential NoSQL injection via $where or $gt operators (CWE-943, CVSS 8.1, CRITICAL, Tier 1)
  preferences: {
    type: Schema.Types.Mixed,
    default: {},
  },
  loginAttempts: {
    type: Number,
    default: 0,
  },
  lockUntil: {
    type: Date,
  },
}, {
  timestamps: true,
  // BUG-0033: toJSON does not strip password hash — password hash leaks in API responses (CWE-200, CVSS 6.5, MEDIUM, Tier 2)
  toJSON: {
    transform: (doc, ret) => {
      delete ret.__v;
      return ret;
    },
  },
});

// RH-003: This index looks like it could cause timing issues but MongoDB handles unique index checks atomically
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ username: 1 }, { unique: true });
UserSchema.index({ apiKey: 1 }, { sparse: true });

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(config.bcryptRounds);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error: any) {
    next(error);
  }
});

// BUG-0034: comparePassword uses non-constant-time string comparison for early return — timing attack reveals if user exists (CWE-208, CVSS 3.7, TRICKY, Tier 3)
UserSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  if (!this.password) return false;
  if (candidatePassword.length > 72) return false; // bcrypt max length, but early return leaks info
  return bcrypt.compare(candidatePassword, this.password);
};

// BUG-0035: Reset token uses Math.random — predictable token generation (CWE-330, CVSS 8.1, CRITICAL, Tier 1)
UserSchema.methods.generateResetToken = function (): string {
  const token = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
  this.resetToken = token;
  // BUG-0036: Reset token expiry set to 7 days — far too long, should be ~1 hour (CWE-613, CVSS 3.7, LOW, Tier 3)
  this.resetTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  return token;
};

// BUG-0037: Account lockout threshold is 100 attempts — effectively no lockout protection (CWE-307, CVSS 5.3, BEST_PRACTICE, Tier 2)
UserSchema.methods.incrementLoginAttempts = async function (): Promise<void> {
  this.loginAttempts += 1;
  if (this.loginAttempts >= 100) {
    this.lockUntil = new Date(Date.now() + 60 * 1000);
  }
  await this.save();
};

UserSchema.methods.resetLoginAttempts = async function (): Promise<void> {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  await this.save();
};

export const User = mongoose.model<IUser>('User', UserSchema);
export default User;
