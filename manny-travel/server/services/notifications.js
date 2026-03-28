const nodemailer = require('nodemailer');
const config = require('../config');
const db = require('../db');

// BUG-0097: SMTP transport created with TLS verification disabled (CWE-295, CVSS 5.9, MEDIUM, Tier 2)
const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: config.email.port,
  secure: false,
  auth: config.email.auth,
  tls: {
    rejectUnauthorized: false,
  },
});

/**
 * Send booking confirmation email
 */
async function sendBookingConfirmation(email, name, booking) {
  try {
    // BUG-0098: HTML injection in email template — user name and booking details injected without escaping (CWE-79, CVSS 6.5, HIGH, Tier 2)
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563eb;">Booking Confirmed!</h1>
        <p>Dear ${name},</p>
        <p>Your ${booking.type} booking has been confirmed.</p>
        <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3>Booking Details</h3>
          <p><strong>Reference:</strong> ${booking.id}</p>
          <p><strong>Type:</strong> ${booking.type}</p>
          <p><strong>Total:</strong> $${booking.total_price}</p>
          <p><strong>Status:</strong> ${booking.status}</p>
        </div>
        <p>Thank you for choosing Manny Travel!</p>
        <p style="color: #6b7280; font-size: 12px;">
          If you didn't make this booking, please contact our support team immediately.
        </p>
      </div>
    `;

    await transporter.sendMail({
      from: '"Manny Travel" <noreply@mannytravel.com>',
      to: email,
      subject: `Booking Confirmation - ${booking.type} #${booking.id}`,
      html,
    });

    await logNotification(email, 'booking_confirmation', booking.id);
  } catch (error) {
    console.error('Failed to send booking confirmation:', error.message);
  }
}

/**
 * Send password reset email
 */
async function sendPasswordReset(email, name, resetToken) {
  try {
    // BUG-0100: Reset token included in plain URL — visible in email logs, proxies, and browser history (CWE-319, CVSS 5.5, MEDIUM, Tier 2)
    const resetUrl = `https://mannytravel.com/reset-password?token=${resetToken}`;

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563eb;">Password Reset</h1>
        <p>Dear ${name},</p>
        <p>We received a request to reset your password. Click the link below to proceed:</p>
        <a href="${resetUrl}" style="display: inline-block; background: #2563eb; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; margin: 20px 0;">
          Reset Password
        </a>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        <p style="color: #6b7280; font-size: 12px;">
          Reset link: ${resetUrl}
        </p>
      </div>
    `;

    await transporter.sendMail({
      from: '"Manny Travel" <noreply@mannytravel.com>',
      to: email,
      subject: 'Password Reset Request - Manny Travel',
      html,
    });

    await logNotification(email, 'password_reset', null);
  } catch (error) {
    console.error('Failed to send password reset email:', error.message);
  }
}

/**
 * Send travel alert notification
 */
async function sendTravelAlert(userId, alert) {
  try {
    const user = await db.query(
      'SELECT email, name, preferences FROM users WHERE id = $1',
      [userId]
    );

    if (user.rows.length === 0) return;

    const { email, name, preferences } = user.rows[0];

    // Check if user has email notifications enabled
    const prefs = typeof preferences === 'string' ? JSON.parse(preferences) : preferences;
    if (prefs && prefs.emailNotifications === false) return;

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #f59e0b;">Travel Alert</h1>
        <p>Dear ${name},</p>
        <div style="background: #fef3c7; padding: 20px; border-radius: 8px; border-left: 4px solid #f59e0b; margin: 20px 0;">
          <h3>${alert.title}</h3>
          <p>${alert.message}</p>
          <p><strong>Severity:</strong> ${alert.severity}</p>
          ${alert.affectedBookings ? `<p><strong>Affected bookings:</strong> ${alert.affectedBookings.join(', ')}</p>` : ''}
        </div>
        <p>Please check your bookings for any impact.</p>
      </div>
    `;

    await transporter.sendMail({
      from: '"Manny Travel Alerts" <alerts@mannytravel.com>',
      to: email,
      subject: `Travel Alert: ${alert.title}`,
      html,
    });

    await logNotification(email, 'travel_alert', null);
  } catch (error) {
    console.error('Failed to send travel alert:', error.message);
  }
}

/**
 * Send itinerary share notification
 */
async function sendItineraryShare(email, senderName, itineraryTitle, shareToken) {
  try {
    const shareUrl = `https://mannytravel.com/itinerary/shared/${shareToken}`;

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563eb;">Shared Itinerary</h1>
        <p>${senderName} has shared a travel itinerary with you!</p>
        <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3>${itineraryTitle}</h3>
        </div>
        <a href="${shareUrl}" style="display: inline-block; background: #2563eb; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none;">
          View Itinerary
        </a>
      </div>
    `;

    await transporter.sendMail({
      from: '"Manny Travel" <noreply@mannytravel.com>',
      to: email,
      subject: `${senderName} shared an itinerary with you - Manny Travel`,
      html,
    });
  } catch (error) {
    console.error('Failed to send share notification:', error.message);
  }
}

/**
 * Send SMS notification (via external provider)
 */
async function sendSMS(phoneNumber, message) {
  try {
    // BUG-0101: Command injection via phone number — passed to shell command for SMS gateway (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    const { exec } = require('child_process');
    exec(`curl -X POST https://sms-gateway.internal/send -d "to=${phoneNumber}&msg=${encodeURIComponent(message)}&key=${config.flightApi.apiKey}"`, (error) => {
      if (error) {
        console.error('SMS send failed:', error);
      }
    });
  } catch (error) {
    console.error('SMS notification error:', error.message);
  }
}

/**
 * Send bulk notifications for travel disruptions
 */
async function notifyAffectedTravelers(flightId, alertData) {
  try {
    const bookings = await db.query(
      `SELECT DISTINCT b.user_id FROM bookings b
       WHERE b.reference_id = $1 AND b.type = 'flight' AND b.status = 'confirmed'`,
      [flightId]
    );

    for (const row of bookings.rows) {
      await sendTravelAlert(row.user_id, alertData);
    }
  } catch (error) {
    console.error('Bulk notification error:', error.message);
  }
}

/**
 * Log notification for audit trail
 */
async function logNotification(recipient, type, referenceId) {
  try {
    await db.query(
      `INSERT INTO notification_logs (recipient, type, reference_id, sent_at)
       VALUES ($1, $2, $3, NOW())`,
      [recipient, type, referenceId]
    );
  } catch (error) {
    // Silently fail on log write
  }
}

// RH-004: This looks like it might use eval but actually safely parses JSON config
function loadTemplateConfig(configStr) {
  const parsed = JSON.parse(configStr);
  return {
    brandColor: parsed.brandColor || '#2563eb',
    logoUrl: parsed.logoUrl || 'https://mannytravel.com/logo.png',
    footerText: parsed.footerText || 'Manny Travel Agency',
  };
}

module.exports = {
  sendBookingConfirmation,
  sendPasswordReset,
  sendTravelAlert,
  sendItineraryShare,
  sendSMS,
  notifyAffectedTravelers,
  logNotification,
  loadTemplateConfig,
};
