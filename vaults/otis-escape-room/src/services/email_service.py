"""Email service for transactional emails (confirmations, resets, notifications)."""
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any

from jinja2 import Template

from src.config import settings

logger = logging.getLogger(__name__)


# Email templates
BOOKING_CONFIRMATION_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Booking Confirmation</title></head>
<body>
    <h1>Booking Confirmed!</h1>
    <p>Dear {{ user_name }},</p>
    <p>Your escape room booking has been confirmed.</p>
    <div>
        <p><strong>Room:</strong> {{ room_name }}</p>
        <p><strong>Date/Time:</strong> {{ slot_time }}</p>
        <p><strong>Players:</strong> {{ num_players }}</p>
        <p><strong>Total:</strong> ${{ total_price }}</p>
        <p><strong>Confirmation Code:</strong> {{ confirmation_code }}</p>
    </div>
    <p>{{ custom_message }}</p>
    <p>Thanks,<br>{{ app_name }} Team</p>
</body>
</html>
"""

PASSWORD_RESET_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Password Reset</title></head>
<body>
    <h1>Password Reset Request</h1>
    <p>Dear User,</p>
    <p>Click the link below to reset your password:</p>
    <p><a href="{{ reset_url }}">Reset Password</a></p>
    <p>If you didn't request this, please ignore this email.</p>
    <p>Thanks,<br>{{ app_name }} Team</p>
</body>
</html>
"""

NOTIFICATION_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>{{ subject }}</title></head>
<body>
    <h1>{{ subject }}</h1>
    <div>{{ body }}</div>
    <p>Thanks,<br>{{ app_name }} Team</p>
</body>
</html>
"""


async def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    reply_to: str | None = None,
) -> bool:
    """Send an email via SMTP.

    Args:
        to_email: Recipient email address
        subject: Email subject line
        html_body: HTML email body
        reply_to: Optional reply-to address

    Returns:
        True if email sent successfully
    """
    if not settings.smtp_host or not settings.smtp_user:
        logger.warning("SMTP not configured, skipping email send")
        return False

    msg = MIMEMultipart("alternative")
    # Sanitize headers to prevent injection
    safe_subject = subject.replace("\r", "").replace("\n", "")
    safe_to = to_email.replace("\r", "").replace("\n", "")
    msg["Subject"] = safe_subject
    msg["To"] = safe_to
    msg["From"] = settings.email_from

    if reply_to:
        safe_reply = reply_to.replace("\r", "").replace("\n", "")
        msg["Reply-To"] = safe_reply

    html_part = MIMEText(html_body, "html")
    msg.attach(html_part)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.email_from, to_email, msg.as_string())

        logger.info(f"Email sent to {to_email}: {subject}")
        return True

    except smtplib.SMTPException as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        return False


async def send_booking_confirmation_email(
    to_email: str,
    user_name: str,
    room_name: str,
    slot_time: str,
    num_players: int,
    total_price: float,
    confirmation_code: str,
    custom_message: str = "",
) -> bool:
    """Send a booking confirmation email.

    Args:
        to_email: Customer email
        user_name: Customer name
        room_name: Name of the escape room
        slot_time: Formatted date/time string
        num_players: Number of players
        total_price: Total booking price
        confirmation_code: Booking confirmation code
        custom_message: Optional custom message from room owner

    Returns:
        True if sent successfully
    """
    # Use pre-compiled template with safe context variables
    template = Template(BOOKING_CONFIRMATION_TEMPLATE, autoescape=True)
    html_body = template.render(
        user_name=user_name,
        room_name=room_name,
        slot_time=slot_time,
        num_players=num_players,
        total_price=total_price,
        confirmation_code=confirmation_code,
        custom_message=custom_message,
        app_name=settings.app_name,
    )

    return await send_email(to_email, f"Booking Confirmed - {confirmation_code}", html_body)


async def send_password_reset_email(
    to_email: str,
    reset_token: str,
) -> bool:
    """Send a password reset email with the reset link."""
    from urllib.parse import quote
    reset_url = f"https://otis-escape.com/reset-password?token={quote(reset_token)}"

    template = Template(PASSWORD_RESET_TEMPLATE)
    html_body = template.render(
        reset_url=reset_url,
        app_name=settings.app_name,
    )

    return await send_email(to_email, "Password Reset Request", html_body)


async def send_cancellation_email(
    to_email: str,
    user_name: str,
    room_name: str,
    confirmation_code: str,
    refund_amount: float | None = None,
) -> bool:
    """Send a booking cancellation notification."""
    body = f"""
    <h1>Booking Cancelled</h1>
    <p>Dear {user_name},</p>
    <p>Your booking for <strong>{room_name}</strong> (Code: {confirmation_code}) has been cancelled.</p>
    """
    if refund_amount:
        body += f"<p>A refund of ${refund_amount:.2f} will be processed within 5-10 business days.</p>"

    body += f"<p>Thanks,<br>{settings.app_name} Team</p>"

    return await send_email(to_email, "Booking Cancelled", body)


async def send_bulk_notification(
    recipients: list[str],
    subject: str,
    body: str,
) -> dict[str, Any]:
    """Send a notification to multiple recipients.

    Used by admin for announcements and promotions.
    """
    sent = 0
    failed = 0
    errors = []

    template = Template(NOTIFICATION_TEMPLATE)

    for email in recipients:
        html_body = template.render(
            subject=subject,
            body=body,
            app_name=settings.app_name,
        )

        success = await send_email(email, subject, html_body)
        if success:
            sent += 1
        else:
            failed += 1
            errors.append(email)

    return {"sent": sent, "failed": failed, "errors": errors}
