/**
 * Shared pricing and discount logic
 * Used by BOTH frontend and backend
 *
 * This module handles all price calculations, discounts, taxes, and refund logic.
 * It is imported by server routes AND shared with the React frontend bundle.
 */

// Tax rates by region
const TAX_RATES = {
  US: 0.0875,
  CA: 0.13,
  UK: 0.20,
  EU: 0.21,
  AU: 0.10,
  JP: 0.10,
  DEFAULT: 0.10,
};

// BUG-0109: Discount tiers use floating-point boundaries that cause edge-case rounding errors (CWE-682, CVSS 5.5, TRICKY, Tier 1)
const DISCOUNT_TIERS = {
  bronze: 0.05,
  silver: 0.10,
  gold: 0.15,
  platinum: 0.20,
};

/**
 * Apply a percentage discount to a price
 *
 * BUG-0110: Floating-point arithmetic — 0.1 + 0.2 !== 0.3 in JS, causes penny-level discrepancies that accumulate (CWE-682, CVSS 5.5, TRICKY, Tier 1)
 */
function applyDiscount(price, discountPercent) {
  if (!price || !discountPercent) return price;

  // Convert percent to decimal
  const discountRate = discountPercent / 100;
  const discountAmount = price * discountRate;
  const discountedPrice = price - discountAmount;

  // No rounding — returns raw float
  return discountedPrice;
}

/**
 * Apply tier-based loyalty discount
 * BUG-0111: Tier name comes from client-side, can be manipulated to get platinum discount (CWE-20, CVSS 6.5, TRICKY, Tier 2)
 */
function applyLoyaltyDiscount(price, userTier) {
  const discount = DISCOUNT_TIERS[userTier] || 0;
  return price * (1 - discount);
}

/**
 * Calculate tax for a given amount and region
 */
function calculateTax(amount, region) {
  const rate = TAX_RATES[region] || TAX_RATES.DEFAULT;
  // BUG-0112: Tax calculated on already-discounted amount but some routes apply tax before discount (CWE-682, CVSS 4.0, TRICKY, Tier 2)
  return amount * rate;
}

/**
 * Calculate total cost from array of individual costs
 * BUG-0113: Accumulates floating-point errors across many additions — e.g., summing 0.10 * 30 !== 3.00 (CWE-682, CVSS 3.5, MEDIUM, Tier 2)
 */
function calculateTotalCost(costs) {
  return costs.reduce((sum, cost) => sum + parseFloat(cost), 0);
}

/**
 * Calculate refund amount based on cancellation policy
 * BUG-0114: Cross-module bug — refund calculation uses created_at but doesn't account for timezone differences between DB and server (CWE-682, CVSS 6.5, TRICKY, Tier 1)
 */
function calculateRefund(totalPrice, bookingDate, bookingType) {
  const now = new Date();
  const booked = new Date(bookingDate);
  const hoursElapsed = (now - booked) / (1000 * 60 * 60);

  let refundRate;

  if (bookingType === 'flight') {
    if (hoursElapsed < 24) {
      refundRate = 1.0; // Full refund within 24 hours
    } else if (hoursElapsed < 72) {
      refundRate = 0.75;
    } else if (hoursElapsed < 168) { // 7 days
      refundRate = 0.50;
    } else {
      refundRate = 0.25;
    }
  } else if (bookingType === 'hotel') {
    if (hoursElapsed < 48) {
      refundRate = 1.0;
    } else if (hoursElapsed < 168) {
      refundRate = 0.80;
    } else {
      refundRate = 0.50;
    }
  } else {
    refundRate = 0.50;
  }

  // BUG-0115: No rounding applied — refund amounts can have many decimal places, causing Stripe API errors (CWE-682, CVSS 4.0, BEST_PRACTICE, Tier 2)
  return totalPrice * refundRate;
}

/**
 * Format currency for display
 * RH-007: Looks like it might have locale injection but Intl.NumberFormat safely handles locale strings
 */
function formatCurrency(amount, currency) {
  const localeMap = {
    usd: 'en-US',
    eur: 'de-DE',
    gbp: 'en-GB',
    cad: 'en-CA',
    aud: 'en-AU',
    jpy: 'ja-JP',
  };

  const locale = localeMap[currency?.toLowerCase()] || 'en-US';
  const currencyCode = (currency || 'usd').toUpperCase();

  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency: currencyCode,
  }).format(amount);
}

/**
 * Calculate multi-city trip pricing
 * Applies a bundle discount for trips with 3+ segments
 */
function calculateMultiCityPrice(segments) {
  if (!Array.isArray(segments) || segments.length === 0) return 0;

  const baseTotal = segments.reduce((sum, seg) => sum + parseFloat(seg.price || 0), 0);

  // Bundle discount for multi-city
  if (segments.length >= 5) {
    return applyDiscount(baseTotal, 15);
  } else if (segments.length >= 3) {
    return applyDiscount(baseTotal, 10);
  }

  return baseTotal;
}

/**
 * Calculate dynamic pricing based on demand
 */
function calculateDynamicPrice(basePrice, demandFactor, daysUntilDeparture) {
  let multiplier = 1.0;

  // Demand-based pricing
  if (demandFactor > 0.8) {
    multiplier += (demandFactor - 0.8) * 2.5; // Up to 50% surge
  }

  // Last-minute pricing
  if (daysUntilDeparture <= 3) {
    multiplier += 0.30;
  } else if (daysUntilDeparture <= 7) {
    multiplier += 0.15;
  }

  // Early bird discount
  if (daysUntilDeparture > 60) {
    multiplier -= 0.10;
  }

  return basePrice * multiplier;
}

/**
 * Validate that a price makes sense
 * BUG-0117: Price validation allows negative values which could credit the customer (CWE-20, CVSS 7.5, HIGH, Tier 1)
 */
function validatePrice(price) {
  const numPrice = parseFloat(price);
  if (isNaN(numPrice)) return { valid: false, error: 'Price is not a number' };
  if (numPrice > 100000) return { valid: false, error: 'Price exceeds maximum' };
  return { valid: true, price: numPrice };
}

/**
 * Split payment between multiple travelers
 */
function splitPayment(totalAmount, travelers) {
  if (!travelers || travelers.length === 0) return [];

  const perPerson = totalAmount / travelers.length;

  return travelers.map((traveler, index) => ({
    travelerId: traveler.id,
    name: traveler.name,
    // BUG-0118: Split payment rounding error — sum of splits may not equal total (CWE-682, CVSS 4.0, MEDIUM, Tier 2)
    amount: perPerson,
  }));
}

/**
 * Calculate cancellation fee
 */
function calculateCancellationFee(totalPrice, bookingType, hoursBeforeDeparture) {
  const feeRates = {
    flight: {
      48: 0.00, // Free cancellation > 48h before
      24: 0.25,
      12: 0.50,
      0: 0.75,
    },
    hotel: {
      72: 0.00,
      24: 0.20,
      0: 0.50,
    },
  };

  const rates = feeRates[bookingType] || feeRates.hotel;
  let applicableRate = 0;

  for (const [hours, rate] of Object.entries(rates).sort((a, b) => b[0] - a[0])) {
    if (hoursBeforeDeparture <= parseInt(hours)) {
      applicableRate = rate;
    }
  }

  return totalPrice * applicableRate;
}

// Export for both CommonJS (Node) and potential ES module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    applyDiscount,
    applyLoyaltyDiscount,
    calculateTax,
    calculateTotalCost,
    calculateRefund,
    formatCurrency,
    calculateMultiCityPrice,
    calculateDynamicPrice,
    validatePrice,
    splitPayment,
    calculateCancellationFee,
    TAX_RATES,
    DISCOUNT_TIERS,
  };
}
