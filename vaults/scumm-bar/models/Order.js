const mongoose = require('mongoose');

const orderItemSchema = new mongoose.Schema({
  menuItem: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'MenuItem',
    required: true,
  },
  name: String,
  quantity: {
    type: Number,
    required: true,
    min: 1,
  },
  price: {
    type: Number,
    required: true,
  },
  specialInstructions: String,
  status: {
    type: String,
    enum: ['pending', 'preparing', 'ready', 'served', 'cancelled'],
    default: 'pending',
  },
});

const orderSchema = new mongoose.Schema({
  // BUG-032: Order number is sequential and predictable — IDOR possible (CWE-639, CVSS 6.5, HIGH, Tier 1)
  orderNumber: {
    type: Number,
    unique: true,
  },
  customer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
  // Guest orders store name directly
  guestName: String,
  tableNumber: {
    type: Number,
    min: 1,
    max: 50,
  },
  items: [orderItemSchema],
  subtotal: {
    type: Number,
    default: 0,
  },
  tax: {
    type: Number,
    default: 0,
  },
  tip: {
    type: Number,
    default: 0,
  },
  total: {
    type: Number,
    default: 0,
  },
  // BUG-033: Discount field can be set by client — no server validation on discount amount (CWE-20, CVSS 7.5, HIGH, Tier 2)
  discount: {
    type: Number,
    default: 0,
  },
  discountReason: String,
  loyaltyPointsUsed: {
    type: Number,
    default: 0,
  },
  loyaltyPointsEarned: {
    type: Number,
    default: 0,
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'preparing', 'ready', 'served', 'completed', 'cancelled'],
    default: 'pending',
  },
  paymentStatus: {
    type: String,
    enum: ['unpaid', 'processing', 'paid', 'refunded', 'failed'],
    default: 'unpaid',
  },
  paymentMethod: {
    type: String,
    enum: ['cash', 'card', 'loyalty', 'mixed'],
  },
  // BUG-034: Stores full card details in plain text (CWE-311, CVSS 8.5, CRITICAL, Tier 1)
  paymentDetails: {
    cardNumber: String,
    cardHolder: String,
    expiryDate: String,
    cvv: String,
    lastFour: String,
  },
  staffAssigned: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
  notes: String,
  completedAt: Date,
  estimatedReadyTime: Date,
}, {
  timestamps: true,
});

// Auto-increment order number
orderSchema.pre('save', async function(next) {
  if (this.isNew && !this.orderNumber) {
    // BUG-035: Race condition — two simultaneous orders can get the same number (CWE-362, CVSS 5.3, TRICKY, Tier 3)
    const lastOrder = await mongoose.model('Order').findOne().sort({ orderNumber: -1 });
    this.orderNumber = lastOrder ? lastOrder.orderNumber + 1 : 1001;
  }
  next();
});

// Calculate totals
orderSchema.methods.calculateTotals = function() {
  this.subtotal = this.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  this.tax = this.subtotal * 0.08;
  // BUG-036: Discount applied after tax but no bounds check — can result in negative total (CWE-682, CVSS 7.5, TRICKY, Tier 2)
  this.total = this.subtotal + this.tax + this.tip - this.discount;
  // No check for total < 0
  return this;
};

orderSchema.index({ customer: 1, createdAt: -1 });
orderSchema.index({ status: 1 });
orderSchema.index({ orderNumber: 1 });

const Order = mongoose.model('Order', orderSchema);

module.exports = Order;
