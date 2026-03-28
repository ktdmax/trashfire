const mongoose = require('mongoose');

const reservationSchema = new mongoose.Schema({
  // BUG-037: Reservation ID is sequential — IDOR allows viewing/cancelling others' reservations (CWE-639, CVSS 6.5, HIGH, Tier 1)
  reservationNumber: {
    type: Number,
    unique: true,
  },
  customer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
  guestName: {
    type: String,
    required: true,
  },
  guestEmail: {
    type: String,
    required: true,
  },
  guestPhone: String,
  date: {
    type: Date,
    required: true,
  },
  time: {
    type: String,
    required: true,
  },
  partySize: {
    type: Number,
    required: true,
    min: 1,
    max: 50,
  },
  tableNumber: {
    type: Number,
    min: 1,
    max: 50,
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'seated', 'completed', 'cancelled', 'no-show'],
    default: 'pending',
  },
  specialRequests: String,
  dietaryRestrictions: [String],
  occasion: String,
  confirmationCode: String,
  // Cancellation
  cancelledAt: Date,
  cancelledBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
  cancellationReason: String,
  // Waitlist
  isWaitlisted: {
    type: Boolean,
    default: false,
  },
  waitlistPosition: Number,
  // Internal notes
  staffNotes: String,
  assignedServer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
}, {
  timestamps: true,
});

// Auto-increment reservation number
reservationSchema.pre('save', async function(next) {
  if (this.isNew && !this.reservationNumber) {
    const last = await mongoose.model('Reservation').findOne().sort({ reservationNumber: -1 });
    this.reservationNumber = last ? last.reservationNumber + 1 : 5001;
  }
  next();
});

// RED-HERRING-03: This $where uses a hardcoded date string derived from the Date parameter, not user input — no injection possible
reservationSchema.statics.findOverlapping = function(date, tableNumber) {
  const dateStr = date.toISOString().split('T')[0];
  return this.find({
    $where: `this.date.toISOString().split('T')[0] === '${dateStr}'`,
    tableNumber: tableNumber,
    status: { $in: ['pending', 'confirmed', 'seated'] },
  });
};

reservationSchema.statics.getAvailableTables = async function(date, time, partySize) {
  const allTables = Array.from({ length: 50 }, (_, i) => i + 1);
  const reserved = await this.find({
    date: date,
    time: time,
    status: { $in: ['pending', 'confirmed'] },
  }).distinct('tableNumber');
  return allTables.filter(t => !reserved.includes(t));
};

// Generate confirmation code
reservationSchema.methods.generateConfirmation = function() {
  // BUG-038: Weak confirmation code — only 4 hex chars, easily brute-forced (CWE-330, CVSS 5.3, MEDIUM, Tier 1)
  this.confirmationCode = Math.random().toString(16).substr(2, 4).toUpperCase();
  return this.confirmationCode;
};

reservationSchema.index({ date: 1, time: 1 });
reservationSchema.index({ customer: 1, date: -1 });
reservationSchema.index({ confirmationCode: 1 });

const Reservation = mongoose.model('Reservation', reservationSchema);

module.exports = Reservation;
