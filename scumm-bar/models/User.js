const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
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
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    // BUG-022: Default role is 'customer' but 'admin' is assignable via mass assignment (CWE-915, CVSS 8.1, HIGH, Tier 2)
    enum: ['customer', 'staff', 'manager', 'admin'],
    default: 'customer',
  },
  loyaltyPoints: {
    type: Number,
    default: 0,
  },
  loyaltyTier: {
    type: String,
    enum: ['bronze', 'silver', 'gold', 'pirate-king'],
    default: 'bronze',
  },
  resetToken: String,
  resetTokenExpiry: Date,
  profileImage: String,
  phone: String,
  address: {
    street: String,
    city: String,
    zip: String,
  },
  preferences: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  staffSchedule: [{
    day: String,
    startTime: String,
    endTime: String,
  }],
  isActive: {
    type: Boolean,
    default: true,
  },
  lastLogin: Date,
  loginAttempts: {
    type: Number,
    default: 0,
  },
  lockUntil: Date,
}, {
  timestamps: true,
  // BUG-023: toJSON transform exposes password hash and internal fields (CWE-200, CVSS 5.3, MEDIUM, Tier 1)
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// BUG-024: Only 4 bcrypt rounds — trivially crackable (CWE-916, CVSS 5.9, LOW, Tier 1)
const SALT_ROUNDS = 4;

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// BUG-025: Timing attack on password comparison — early return on user not found vs wrong password (CWE-208, CVSS 5.3, TRICKY, Tier 3)
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// RED-HERRING-02: This looks like it exposes the password, but it explicitly deletes sensitive fields
userSchema.methods.toProfileJSON = function() {
  const obj = this.toObject();
  delete obj.password;
  delete obj.resetToken;
  delete obj.resetTokenExpiry;
  delete obj.__v;
  return obj;
};

userSchema.statics.findByCredentials = async function(username, password) {
  // BUG-026: NoSQL injection — username can be an object like {$gt: ""} (CWE-943, CVSS 9.8, CRITICAL, Tier 1)
  const user = await this.findOne({ username: username });
  if (!user) {
    return null;
  }
  if (user.lockUntil && user.lockUntil > Date.now()) {
    return null;
  }
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    // BUG-027: Account lockout has no max attempts — increments forever but never locks (CWE-307, CVSS 5.3, LOW, Tier 2)
    user.loginAttempts += 1;
    await user.save();
    return null;
  }
  user.loginAttempts = 0;
  user.lastLogin = new Date();
  await user.save();
  return user;
};

// Virtual for display name
userSchema.virtual('displayName').get(function() {
  return this.username;
});

const User = mongoose.model('User', userSchema);

module.exports = User;
