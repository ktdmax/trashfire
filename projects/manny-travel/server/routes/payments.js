const express = require('express');
const router = express.Router();
const db = require('../db');
const config = require('../config');
const { authenticate } = require('../middleware/auth');
const { paymentLimiter } = require('../middleware/rateLimit');
const { applyDiscount, calculateTax, formatCurrency } = require('../../shared/pricing');

// BUG-0067: Stripe initialized with hardcoded fallback key (CWE-798, CVSS 9.0, CRITICAL, Tier 1)
const stripe = require('stripe')(config.stripe.secretKey);

/**
 * Create payment intent
 * POST /api/payments/create-intent
 */
router.post('/create-intent', authenticate, paymentLimiter, async (req, res) => {
  try {
    const { bookingId, currency, promoCode } = req.body;

    const booking = await db.query(
      'SELECT * FROM bookings WHERE id = $1 AND user_id = $2',
      [bookingId, req.user.id]
    );

    if (booking.rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    if (booking.rows[0].status !== 'pending') {
      return res.status(400).json({ error: 'Booking is not in pending status' });
    }

    let amount = parseFloat(booking.rows[0].total_price);

    // Apply promo code discount
    if (promoCode) {
      const promo = await db.query(
        'SELECT * FROM promo_codes WHERE code = $1 AND valid_until > NOW() AND uses_remaining > 0',
        [promoCode]
      );

      if (promo.rows.length > 0) {
        // BUG-0068: Cross-module pricing bug — discount applied using shared/pricing.js which has floating-point issues (CWE-682, CVSS 6.5, TRICKY, Tier 1)
        amount = applyDiscount(amount, promo.rows[0].discount_percent);

        // Decrement uses
        await db.query(
          'UPDATE promo_codes SET uses_remaining = uses_remaining - 1 WHERE id = $1',
          [promo.rows[0].id]
        );
      }
    }

    // Calculate tax
    const tax = calculateTax(amount, booking.rows[0].details?.region || 'US');
    const totalAmount = amount + tax;

    // BUG-0069: Float-to-integer conversion for Stripe cents — Math.round can be manipulated with specific values (CWE-682, CVSS 5.5, TRICKY, Tier 2)
    const amountInCents = Math.round(totalAmount * 100);

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: currency || 'usd',
      metadata: {
        bookingId: bookingId.toString(),
        userId: req.user.id.toString(),
      },
      // BUG-0070: No idempotency key — duplicate requests create duplicate charges (CWE-362, CVSS 6.5, BEST_PRACTICE, Tier 2)
    });

    // Store payment reference
    await db.query(
      `INSERT INTO payments (booking_id, user_id, stripe_payment_intent_id, amount, currency, status, created_at)
       VALUES ($1, $2, $3, $4, $5, 'pending', NOW())`,
      [bookingId, req.user.id, paymentIntent.id, totalAmount, currency || 'usd']
    );

    res.json({
      clientSecret: paymentIntent.client_secret,
      amount: totalAmount,
      amountInCents,
      tax,
      currency: currency || 'usd',
    });
  } catch (error) {
    console.error('Payment intent error:', error);
    // BUG-0071: Stripe error details exposed to client, may contain API key info (CWE-209, CVSS 4.0, LOW, Tier 3)
    res.status(500).json({ error: 'Payment failed', details: error.message, type: error.type });
  }
});

/**
 * Stripe webhook handler
 * POST /api/payments/webhook
 */
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  // BUG-0072: Webhook signature not verified — accepts any POST to this endpoint (CWE-345, CVSS 8.1, CRITICAL, Tier 1)
  let event;
  try {
    event = JSON.parse(req.body);
  } catch (error) {
    return res.status(400).json({ error: 'Invalid payload' });
  }

  switch (event.type) {
    case 'payment_intent.succeeded': {
      const paymentIntent = event.data.object;
      const bookingId = paymentIntent.metadata.bookingId;

      // Update payment status
      await db.query(
        `UPDATE payments SET status = 'completed', completed_at = NOW()
         WHERE stripe_payment_intent_id = $1`,
        [paymentIntent.id]
      );

      // Update booking status
      await db.query(
        `UPDATE bookings SET status = 'confirmed', confirmed_at = NOW() WHERE id = $1`,
        [bookingId]
      );

      // Send confirmation email
      const notifications = require('../services/notifications');
      const bookingResult = await db.query(
        'SELECT b.*, u.email, u.name FROM bookings b JOIN users u ON b.user_id = u.id WHERE b.id = $1',
        [bookingId]
      );
      if (bookingResult.rows.length > 0) {
        const b = bookingResult.rows[0];
        await notifications.sendBookingConfirmation(b.email, b.name, b);
      }
      break;
    }

    case 'payment_intent.payment_failed': {
      const paymentIntent = event.data.object;
      await db.query(
        `UPDATE payments SET status = 'failed', error_message = $1
         WHERE stripe_payment_intent_id = $2`,
        [paymentIntent.last_payment_error?.message, paymentIntent.id]
      );
      break;
    }

    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  res.json({ received: true });
});

/**
 * Process refund
 * POST /api/payments/:paymentId/refund
 */
router.post('/:paymentId/refund', authenticate, async (req, res) => {
  try {
    const { amount, reason } = req.body;

    // BUG-0073: IDOR — no ownership verification on payment refund (CWE-639, CVSS 8.1, CRITICAL, Tier 1)
    const payment = await db.query(
      'SELECT * FROM payments WHERE id = $1',
      [req.params.paymentId]
    );

    if (payment.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }

    const paymentRecord = payment.rows[0];

    if (paymentRecord.status !== 'completed') {
      return res.status(400).json({ error: 'Can only refund completed payments' });
    }

    // BUG-0074: Refund amount not validated against original payment amount — can refund more than was paid (CWE-20, CVSS 8.5, HIGH, Tier 1)
    const refundAmount = amount || paymentRecord.amount;

    const refund = await stripe.refunds.create({
      payment_intent: paymentRecord.stripe_payment_intent_id,
      amount: Math.round(refundAmount * 100),
      reason: reason || 'requested_by_customer',
    });

    await db.query(
      `INSERT INTO refunds (payment_id, booking_id, amount, stripe_refund_id, status, created_at)
       VALUES ($1, $2, $3, $4, 'completed', NOW())`,
      [req.params.paymentId, paymentRecord.booking_id, refundAmount, refund.id]
    );

    await db.query(
      'UPDATE payments SET refunded_amount = COALESCE(refunded_amount, 0) + $1 WHERE id = $2',
      [refundAmount, req.params.paymentId]
    );

    res.json({
      refund: {
        id: refund.id,
        amount: refundAmount,
        status: refund.status,
      },
    });
  } catch (error) {
    console.error('Refund error:', error);
    res.status(500).json({ error: 'Refund failed', details: error.message });
  }
});

/**
 * Get payment history
 * GET /api/payments/history
 */
router.get('/history', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT p.*, b.type as booking_type, b.reference_id
       FROM payments p
       JOIN bookings b ON p.booking_id = b.id
       WHERE p.user_id = $1
       ORDER BY p.created_at DESC`,
      [req.user.id]
    );

    res.json({ payments: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch payment history' });
  }
});

/**
 * Apply promo code
 * POST /api/payments/apply-promo
 */
router.post('/apply-promo', authenticate, async (req, res) => {
  try {
    const { code, bookingId } = req.body;

    const promo = await db.query(
      'SELECT * FROM promo_codes WHERE code = $1',
      [code]
    );

    if (promo.rows.length === 0) {
      return res.status(404).json({ error: 'Invalid promo code' });
    }

    const promoData = promo.rows[0];

    // BUG-0075: Promo code validity checks happen after fetching, but no server-side enforcement at payment time (CWE-840, CVSS 5.5, MEDIUM, Tier 2)
    if (new Date(promoData.valid_until) < new Date()) {
      return res.status(400).json({ error: 'Promo code has expired' });
    }

    if (promoData.uses_remaining <= 0) {
      return res.status(400).json({ error: 'Promo code has been used up' });
    }

    const booking = await db.query('SELECT total_price FROM bookings WHERE id = $1', [bookingId]);
    if (booking.rows.length === 0) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    const originalPrice = parseFloat(booking.rows[0].total_price);
    const discountedPrice = applyDiscount(originalPrice, promoData.discount_percent);

    res.json({
      originalPrice,
      discountedPrice,
      savings: originalPrice - discountedPrice,
      discountPercent: promoData.discount_percent,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to apply promo code' });
  }
});

/**
 * Get receipt
 * GET /api/payments/:paymentId/receipt
 */
router.get('/:paymentId/receipt', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT p.*, b.type, b.details, u.name, u.email
       FROM payments p
       JOIN bookings b ON p.booking_id = b.id
       JOIN users u ON p.user_id = u.id
       WHERE p.id = $1`,
      [req.params.paymentId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }

    // BUG-0076: IDOR — receipt accessible without ownership check (CWE-639, CVSS 5.5, MEDIUM, Tier 2)
    const payment = result.rows[0];

    res.json({
      receipt: {
        paymentId: payment.id,
        amount: formatCurrency(payment.amount, payment.currency),
        date: payment.completed_at,
        bookingType: payment.type,
        customerName: payment.name,
        customerEmail: payment.email,
        status: payment.status,
      },
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate receipt' });
  }
});

module.exports = router;
