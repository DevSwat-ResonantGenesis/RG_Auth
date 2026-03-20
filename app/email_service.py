"""
Email service module for the auth service.

Supports:
- SendGrid (primary)
- Console output (development fallback)

Usage:
    from .email_service import send_email, EmailTemplate
    
    await send_email(
        to="user@example.com",
        template=EmailTemplate.EMAIL_VERIFICATION,
        context={"verification_url": "https://..."}
    )
"""
import asyncio
from enum import Enum
from typing import Any, Dict, Optional
from datetime import datetime, timezone

from .config import settings


class EmailTemplate(str, Enum):
    """Email templates."""
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    LOGIN_NOTIFICATION = "login_notification"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    ACCOUNT_LOCKED = "account_locked"
    WELCOME = "welcome"


# Email templates with subject and body
EMAIL_TEMPLATES: Dict[EmailTemplate, Dict[str, str]] = {
    EmailTemplate.EMAIL_VERIFICATION: {
        "subject": "Verify your email address - ResonantGenesis",
        "html": """
        <h2>Verify Your Email Address</h2>
        <p>Hi {name},</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_url}" style="background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px;">Verify Email</a></p>
        <p>Or copy this link: {verification_url}</p>
        <p>This link expires in 24 hours.</p>
        <p>If you didn't create an account, you can safely ignore this email.</p>
        <br>
        <p>- The ResonantGenesis Team</p>
        """,
    },
    EmailTemplate.PASSWORD_RESET: {
        "subject": "Reset your password - ResonantGenesis",
        "html": """
        <h2>Reset Your Password</h2>
        <p>Hi {name},</p>
        <p>We received a request to reset your password. Click the link below:</p>
        <p><a href="{reset_url}" style="background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px;">Reset Password</a></p>
        <p>Or copy this link: {reset_url}</p>
        <p>This link expires in 1 hour.</p>
        <p>If you didn't request this, you can safely ignore this email.</p>
        <br>
        <p>- The ResonantGenesis Team</p>
        """,
    },
    EmailTemplate.LOGIN_NOTIFICATION: {
        "subject": "New login to your account - ResonantGenesis",
        "html": """
        <h2>New Login Detected</h2>
        <p>Hi {name},</p>
        <p>We noticed a new login to your account:</p>
        <ul>
            <li><strong>Device:</strong> {device_name}</li>
            <li><strong>Location:</strong> {location}</li>
            <li><strong>IP Address:</strong> {ip_address}</li>
            <li><strong>Time:</strong> {login_time}</li>
        </ul>
        <p>If this was you, you can ignore this email.</p>
        <p>If you don't recognize this activity, please <a href="{security_url}">secure your account</a> immediately.</p>
        <br>
        <p>- The ResonantGenesis Team</p>
        """,
    },
    EmailTemplate.MFA_ENABLED: {
        "subject": "Two-factor authentication enabled - ResonantGenesis",
        "html": """
        <h2>Two-Factor Authentication Enabled</h2>
        <p>Hi {name},</p>
        <p>Two-factor authentication has been successfully enabled on your account.</p>
        <p>Your account is now more secure. You'll need to enter a code from your authenticator app when logging in.</p>
        <p>If you didn't make this change, please <a href="{security_url}">secure your account</a> immediately.</p>
        <br>
        <p>- The ResonantGenesis Team</p>
        """,
    },
    EmailTemplate.ACCOUNT_LOCKED: {
        "subject": "Account locked - ResonantGenesis",
        "html": """
        <h2>Account Temporarily Locked</h2>
        <p>Hi {name},</p>
        <p>Your account has been temporarily locked due to multiple failed login attempts.</p>
        <p>You can try again in {lockout_minutes} minutes, or <a href="{reset_url}">reset your password</a>.</p>
        <p>If you didn't attempt to log in, someone may be trying to access your account.</p>
        <br>
        <p>- The ResonantGenesis Team</p>
        """,
    },
    EmailTemplate.WELCOME: {
        "subject": "Welcome to ResonantGenesis!",
        "html": """
        <h2>Welcome to ResonantGenesis!</h2>
        <p>Hi {name},</p>
        <p>Thank you for joining ResonantGenesis. We're excited to have you!</p>
        <p>Get started by:</p>
        <ul>
            <li>Verifying your email address</li>
            <li>Setting up two-factor authentication</li>
            <li>Creating your first AI agent</li>
        </ul>
        <p><a href="{dashboard_url}" style="background-color: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px;">Go to Dashboard</a></p>
        <br>
        <p>- The ResonantGenesis Team</p>
        """,
    },
}


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


async def send_email(
    to: str,
    template: EmailTemplate,
    context: Dict[str, Any],
    from_email: Optional[str] = None,
    from_name: Optional[str] = None,
) -> bool:
    """
    Send an email using the configured email service.
    
    Args:
        to: Recipient email address
        template: Email template to use
        context: Template context variables
        from_email: Override sender email
        from_name: Override sender name
    
    Returns:
        True if email was sent successfully
    """
    template_data = EMAIL_TEMPLATES.get(template)
    if not template_data:
        print(f"[EMAIL] Unknown template: {template}")
        return False
    
    subject = template_data["subject"]
    html_body = template_data["html"].format(**context)
    
    sender_email = from_email or settings.EMAIL_FROM_ADDRESS
    sender_name = from_name or settings.EMAIL_FROM_NAME
    
    # Check if SendGrid is configured (preferred for production - more reliable)
    if settings.SENDGRID_API_KEY:
        result = await _send_via_sendgrid(
            to=to,
            subject=subject,
            html_body=html_body,
            from_email=sender_email,
            from_name=sender_name,
        )
        if result:
            return True
        # Fall through to SMTP if SendGrid fails
    
    # Check if SMTP is configured (Google Workspace, etc.)
    if settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD:
        return await _send_via_smtp(
            to=to,
            subject=subject,
            html_body=html_body,
            from_email=sender_email,
            from_name=sender_name,
        )
    
    # Fallback to console in development
    if settings.ENVIRONMENT == "development":
        return _send_to_console(
            to=to,
            subject=subject,
            html_body=html_body,
            from_email=sender_email,
        )
    
    # In production without email configured, log warning
    print(f"[EMAIL WARNING] No email provider configured, email not sent to {to}")
    return False


async def _send_via_smtp(
    to: str,
    subject: str,
    html_body: str,
    from_email: str,
    from_name: str,
) -> bool:
    """Send email via SMTP (Google Workspace, etc.)."""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = to
        
        # Attach HTML content
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        # Send via SMTP (run in thread to not block)
        def send_sync():
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)
        
        # Run in executor to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, send_sync)
        
        print(f"[EMAIL] Sent via SMTP to {to}: {subject}")
        return True
        
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send via SMTP: {e}")
        return False


async def _send_via_sendgrid(
    to: str,
    subject: str,
    html_body: str,
    from_email: str,
    from_name: str,
) -> bool:
    """Send email via SendGrid API."""
    try:
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={
                    "Authorization": f"Bearer {settings.SENDGRID_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "personalizations": [{"to": [{"email": to}]}],
                    "from": {"email": from_email, "name": from_name},
                    "subject": subject,
                    "content": [{"type": "text/html", "value": html_body}],
                },
                timeout=10.0,
            )
            
            if response.status_code in (200, 201, 202):
                print(f"[EMAIL] Sent to {to}: {subject}")
                return True
            else:
                print(f"[EMAIL ERROR] SendGrid returned {response.status_code}: {response.text}")
                return False
                
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send via SendGrid: {e}")
        return False


def _send_to_console(
    to: str,
    subject: str,
    html_body: str,
    from_email: str,
) -> bool:
    """Print email to console for development."""
    # Strip HTML tags for console output
    import re
    text_body = re.sub(r'<[^>]+>', '', html_body)
    text_body = re.sub(r'\s+', ' ', text_body).strip()
    
    print(f"\n{'='*60}")
    print("EMAIL (DEV MODE - Not actually sent)")
    print(f"{'='*60}")
    print(f"To: {to}")
    print(f"From: {from_email}")
    print(f"Subject: {subject}")
    print(f"Time: {_utcnow().isoformat()}")
    print(f"{'-'*60}")
    print(text_body[:500])
    if len(text_body) > 500:
        print("... (truncated)")
    print(f"{'='*60}\n")
    
    return True


# Convenience functions for common emails
async def send_verification_email(
    to: str,
    verification_url: str,
    name: Optional[str] = None,
) -> bool:
    """Send email verification email."""
    return await send_email(
        to=to,
        template=EmailTemplate.EMAIL_VERIFICATION,
        context={
            "name": name or "there",
            "verification_url": verification_url,
        },
    )


async def send_password_reset_email(
    to: str,
    reset_url: str,
    name: Optional[str] = None,
) -> bool:
    """Send password reset email."""
    return await send_email(
        to=to,
        template=EmailTemplate.PASSWORD_RESET,
        context={
            "name": name or "there",
            "reset_url": reset_url,
        },
    )


async def send_login_notification_email(
    to: str,
    device_name: str,
    location: Optional[str],
    ip_address: Optional[str],
    name: Optional[str] = None,
) -> bool:
    """Send login notification email."""
    return await send_email(
        to=to,
        template=EmailTemplate.LOGIN_NOTIFICATION,
        context={
            "name": name or "there",
            "device_name": device_name,
            "location": location or "Unknown",
            "ip_address": ip_address or "Unknown",
            "login_time": _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "security_url": f"{settings.FRONTEND_URL}/settings/security",
        },
    )
