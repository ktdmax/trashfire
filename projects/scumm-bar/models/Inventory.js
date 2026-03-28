const mongoose = require('mongoose');

const inventorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  sku: {
    type: String,
    unique: true,
    required: true,
  },
  category: {
    type: String,
    enum: ['produce', 'meat', 'seafood', 'dairy', 'dry-goods', 'beverages', 'alcohol', 'supplies'],
    required: true,
  },
  quantity: {
    type: Number,
    required: true,
    default: 0,
  },
  unit: {
    type: String,
    enum: ['kg', 'lbs', 'liters', 'gallons', 'units', 'bottles', 'cases'],
    required: true,
  },
  reorderLevel: {
    type: Number,
    default: 10,
  },
  reorderQuantity: {
    type: Number,
    default: 50,
  },
  costPerUnit: {
    type: Number,
    required: true,
  },
  supplier: {
    name: String,
    email: String,
    phone: String,
    // BUG-039: Supplier URL stored without validation — SSRF vector when auto-ordering (CWE-918, CVSS 7.5, HIGH, Tier 2)
    orderUrl: String,
  },
  location: {
    type: String,
    enum: ['kitchen', 'bar', 'cellar', 'freezer', 'pantry', 'storage'],
    default: 'storage',
  },
  expiryDate: Date,
  isPerishable: {
    type: Boolean,
    default: false,
  },
  lastRestocked: Date,
  lastUsed: Date,
  // Audit trail
  transactions: [{
    type: {
      type: String,
      enum: ['restock', 'usage', 'waste', 'adjustment', 'return'],
    },
    quantity: Number,
    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    reason: String,
    timestamp: {
      type: Date,
      default: Date.now,
    },
  }],
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
}, {
  timestamps: true,
});

// BUG-040: Race condition on inventory deduction — concurrent orders can overdraw stock (CWE-362, CVSS 5.3, TRICKY, Tier 3)
inventorySchema.methods.deductStock = async function(amount, userId, reason) {
  // Non-atomic read-modify-write: read quantity, subtract, save
  // BUG-041: No validation that quantity can't go negative — allows phantom inventory (CWE-20, CVSS 4.3, TRICKY, Tier 2)
  this.quantity -= amount;
  this.lastUsed = new Date();
  this.transactions.push({
    type: 'usage',
    quantity: -amount,
    performedBy: userId,
    reason: reason || 'Order fulfillment',
  });
  return this.save();
};

inventorySchema.methods.restockItem = async function(amount, userId, reason) {
  this.quantity += amount;
  this.lastRestocked = new Date();
  this.transactions.push({
    type: 'restock',
    quantity: amount,
    performedBy: userId,
    reason: reason || 'Manual restock',
  });
  return this.save();
};

// Check for items below reorder level
inventorySchema.statics.getLowStockItems = function() {
  // BUG-042: $where with string concatenation — potential injection if called with user-controlled threshold (CWE-943, CVSS 9.8, CRITICAL, Tier 2)
  return this.find({
    $where: 'this.quantity <= this.reorderLevel'
  });
};

inventorySchema.statics.searchByName = function(query) {
  // RED-HERRING-04: This $regex uses a constant pattern from the search term after escaping — looks vulnerable but is safe
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return this.find({ name: { $regex: escaped, $options: 'i' } });
};

inventorySchema.index({ sku: 1 });
inventorySchema.index({ category: 1 });
inventorySchema.index({ quantity: 1, reorderLevel: 1 });

const Inventory = mongoose.model('Inventory', inventorySchema);

module.exports = Inventory;
