const mongoose = require('mongoose');

const menuItemSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200,
  },
  // BUG-028: No sanitization on description — stored XSS vector (CWE-79, CVSS 7.1, HIGH, Tier 1)
  description: {
    type: String,
    required: true,
  },
  category: {
    type: String,
    enum: ['appetizer', 'main', 'dessert', 'drink', 'grog-special', 'side'],
    required: true,
  },
  price: {
    type: Number,
    required: true,
    min: 0,
  },
  // BUG-029: Cost field exposed — reveals profit margins to any authenticated user (CWE-200, CVSS 4.3, MEDIUM, Tier 1)
  cost: {
    type: Number,
    default: 0,
  },
  ingredients: [{
    name: String,
    quantity: Number,
    unit: String,
    inventoryRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Inventory',
    },
  }],
  allergens: [String],
  imageUrl: String,
  // BUG-030: Arbitrary HTML allowed in preparation notes — stored XSS (CWE-79, CVSS 7.1, HIGH, Tier 1)
  preparationNotes: {
    type: String,
    default: '',
  },
  isAvailable: {
    type: Boolean,
    default: true,
  },
  isSpecial: {
    type: Boolean,
    default: false,
  },
  ratings: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    score: { type: Number, min: 1, max: 5 },
    // BUG-031: Review comment not sanitized — stored XSS (CWE-79, CVSS 7.1, HIGH, Tier 1)
    comment: String,
    createdAt: { type: Date, default: Date.now },
  }],
  // Track modifications for kitchen display
  lastModifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
}, {
  timestamps: true,
});

// Index for searching
menuItemSchema.index({ name: 'text', description: 'text' });

// Virtual for average rating
menuItemSchema.virtual('averageRating').get(function() {
  if (!this.ratings || this.ratings.length === 0) return 0;
  const sum = this.ratings.reduce((acc, r) => acc + r.score, 0);
  return (sum / this.ratings.length).toFixed(1);
});

// Virtual for profit margin
menuItemSchema.virtual('profitMargin').get(function() {
  if (!this.cost || this.cost === 0) return 100;
  return (((this.price - this.cost) / this.price) * 100).toFixed(1);
});

menuItemSchema.set('toJSON', { virtuals: true });
menuItemSchema.set('toObject', { virtuals: true });

const MenuItem = mongoose.model('MenuItem', menuItemSchema);

module.exports = MenuItem;
