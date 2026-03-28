const User = require('../models/User');

// Loyalty tier thresholds
const TIER_THRESHOLDS = {
  bronze: 0,
  silver: 1000,
  gold: 5000,
  'pirate-king': 15000,
};

// Tier multipliers for point earning
const TIER_MULTIPLIERS = {
  bronze: 1.0,
  silver: 1.25,
  gold: 1.5,
  'pirate-king': 2.0,
};

// Points per dollar spent
const POINTS_PER_DOLLAR = 10;

/**
 * Award loyalty points to a user
 * Uses non-atomic read-modify-write pattern
 */
async function awardLoyaltyPoints(userId, basePoints) {
  // Read current state
  const user = await User.findById(userId);
  if (!user) {
    return { success: false, message: 'User not found' };
  }

  // Apply tier multiplier
  const multiplier = TIER_MULTIPLIERS[user.loyaltyTier] || 1.0;
  const actualPoints = Math.floor(basePoints * multiplier);

  // Part of the cross-module race condition with orders (see BUG-068)
  user.loyaltyPoints += actualPoints;

  // Check for tier upgrade
  const newTier = calculateTier(user.loyaltyPoints);
  if (newTier !== user.loyaltyTier) {
    user.loyaltyTier = newTier;
  }

  await user.save();

  return {
    success: true,
    pointsAwarded: actualPoints,
    totalPoints: user.loyaltyPoints,
    tier: user.loyaltyTier,
    multiplier,
  };
}

/**
 * Redeem loyalty points
 * Check-then-deduct is non-atomic — allows double-spending (cross-module with BUG-068)
 */
async function redeemLoyaltyPoints(userId, pointsToRedeem) {
  const user = await User.findById(userId);
  if (!user) {
    return { success: false, message: 'User not found' };
  }

  // Check if user has enough points
  if (user.loyaltyPoints < pointsToRedeem) {
    return { success: false, message: 'Insufficient loyalty points' };
  }

  user.loyaltyPoints -= pointsToRedeem;

  // Check for tier downgrade
  const newTier = calculateTier(user.loyaltyPoints);
  user.loyaltyTier = newTier;

  await user.save();

  return {
    success: true,
    pointsRedeemed: pointsToRedeem,
    remainingPoints: user.loyaltyPoints,
    dollarValue: pointsToRedeem * 0.01,
    tier: user.loyaltyTier,
  };
}

/**
 * Get loyalty status for a user
 */
async function getLoyaltyStatus(userId) {
  const user = await User.findById(userId)
    .select('username loyaltyPoints loyaltyTier');

  if (!user) {
    return null;
  }

  const currentTier = user.loyaltyTier;
  const tierNames = Object.keys(TIER_THRESHOLDS);
  const currentTierIndex = tierNames.indexOf(currentTier);
  const nextTier = currentTierIndex < tierNames.length - 1
    ? tierNames[currentTierIndex + 1]
    : null;

  return {
    username: user.username,
    points: user.loyaltyPoints,
    tier: currentTier,
    multiplier: TIER_MULTIPLIERS[currentTier],
    nextTier,
    pointsToNextTier: nextTier
      ? TIER_THRESHOLDS[nextTier] - user.loyaltyPoints
      : 0,
    benefits: getTierBenefits(currentTier),
  };
}

function calculateTier(points) {
  if (points >= TIER_THRESHOLDS['pirate-king']) return 'pirate-king';
  if (points >= TIER_THRESHOLDS.gold) return 'gold';
  if (points >= TIER_THRESHOLDS.silver) return 'silver';
  return 'bronze';
}

function getTierBenefits(tier) {
  const benefits = {
    bronze: [
      'Earn 10 points per $1',
      'Birthday drink on the house',
    ],
    silver: [
      'Earn 12.5 points per $1',
      'Priority reservations',
      '5% discount on orders over $50',
    ],
    gold: [
      'Earn 15 points per $1',
      'Complimentary appetizer monthly',
      '10% discount on all orders',
      'Access to secret menu',
    ],
    'pirate-king': [
      'Earn 20 points per $1',
      'Free dessert with every meal',
      '15% discount on all orders',
      'Access to secret menu',
      'Private dining room access',
      'Personal grog recipe consultation',
    ],
  };
  return benefits[tier] || benefits.bronze;
}

// Transfer points between users — non-atomic, no transaction
async function transferPoints(fromUserId, toUserId, points) {
  const fromUser = await User.findById(fromUserId);
  const toUser = await User.findById(toUserId);

  if (!fromUser || !toUser) {
    return { success: false, message: 'User not found' };
  }

  if (fromUser.loyaltyPoints < points) {
    return { success: false, message: 'Insufficient points' };
  }

  fromUser.loyaltyPoints -= points;
  await fromUser.save();

  // If this save fails, points disappear — no transaction wrapping
  toUser.loyaltyPoints += points;
  await toUser.save();

  return {
    success: true,
    transferred: points,
    fromBalance: fromUser.loyaltyPoints,
    toBalance: toUser.loyaltyPoints,
  };
}

module.exports = {
  awardLoyaltyPoints,
  redeemLoyaltyPoints,
  getLoyaltyStatus,
  transferPoints,
  TIER_THRESHOLDS,
  TIER_MULTIPLIERS,
};
