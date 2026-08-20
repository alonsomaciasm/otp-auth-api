import asyncio
from email.message import EmailMessage
import smtplib

from app.core.config import settings
from app.core.logging import logger
from app.services.otp.base import OTPChannelStrategy
from app.services.otp.console import ConsoleOTPStrategy


class SMTPOTPStrategy(OTPChannelStrategy):
    """
    SMTP OTP delivery strategy supporting Resend, Brevo, Gmail, and custom TLS SMTP servers.
    Provides a high-end, responsive HTML email template with full environment variable customization.
    """

    async def send_otp(self, recipient: str, code: str) -> bool:
        if not settings.SMTP_HOST or not settings.SMTP_USER or not settings.SMTP_PASSWORD:
            logger.error("SMTP settings incomplete. Cannot send email OTP.")
            return False

        expire_minutes = settings.OTP_EXPIRE_SECONDS // 60

        msg = EmailMessage()
        msg["Subject"] = f"🔐 {code} es tu {settings.EMAIL_SUBJECT_PREFIX}"
        msg["From"] = settings.SMTP_FROM_EMAIL or settings.SMTP_USER
        msg["To"] = recipient

        # Plain Text Fallback
        text_body = (
            f"{settings.EMAIL_SUBJECT_PREFIX}\n\n"
            f"{settings.EMAIL_GREETING}\n"
            f"{settings.EMAIL_BODY_TEXT}\n\n"
            f"Tu código de acceso único es: {code}\n"
            f"Este código es válido durante {expire_minutes} minutos.\n\n"
            f"{settings.EMAIL_SECURITY_NOTICE}"
        )
        msg.set_content(text_body)

        # High-End Responsive HTML Email Template (UI/UX & Env Configurable)
        html_body = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{settings.EMAIL_SUBJECT_PREFIX}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #090d16; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f0f4f8;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout: fixed; background-color: #090d16; padding: 40px 10px;">
        <tr>
            <td align="center">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 520px; background: rgba(18, 26, 43, 0.95); border: 1px solid rgba(0, 240, 255, 0.2); border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
                    <!-- Header -->
                    <tr>
                        <td align="center" style="padding: 32px 20px 20px 20px; background: linear-gradient(135deg, #090d16 0%, #121a2b 100%); border-bottom: 1px solid rgba(255,255,255,0.08);">
                            <div style="display: inline-block; width: 48px; height: 48px; line-height: 48px; background: rgba(0, 240, 255, 0.1); border: 1px solid #00f0ff; border-radius: 12px; font-size: 24px;">
                                🛡️
                            </div>
                            <h1 style="margin: 16px 0 4px 0; font-size: 20px; font-weight: 700; color: #ffffff; letter-spacing: -0.5px;">
                                {settings.EMAIL_BRAND_NAME}
                            </h1>
                            <p style="margin: 0; font-size: 13px; color: #8a99ad;">
                                {settings.EMAIL_BRAND_SLOGAN}
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style="padding: 32px 28px;">
                            <p style="margin: 0 0 12px 0; font-size: 15px; color: #d0d7de; line-height: 1.5;">
                                {settings.EMAIL_GREETING}
                            </p>
                            <p style="margin: 0 0 24px 0; font-size: 14px; color: #8a99ad; line-height: 1.5;">
                                {settings.EMAIL_BODY_TEXT}
                            </p>
                            
                            <!-- OTP Box -->
                            <div style="background: rgba(5, 8, 15, 0.8); border: 1px solid #00ff87; border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 24px;">
                                <div style="font-size: 11px; text-transform: uppercase; tracking: 1.5px; color: #8a99ad; margin-bottom: 8px; font-weight: 600;">
                                    CÓDIGO DE VERIFICACIÓN
                                </div>
                                <div style="font-family: 'JetBrains Mono', 'Courier New', Consolas, monospace; font-size: 34px; font-weight: 700; color: #00ff87; letter-spacing: 8px; margin: 4px 0;">
                                    {code}
                                </div>
                                <div style="font-size: 12px; color: #00f0ff; margin-top: 8px;">
                                    ⏱️ Válido durante {expire_minutes} minutos
                                </div>
                            </div>
                            
                            <!-- Security Alert Note -->
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background: rgba(255, 0, 127, 0.08); border-left: 3px solid #ff007f; border-radius: 4px; margin-bottom: 20px;">
                                <tr>
                                    <td style="padding: 12px 16px; font-size: 12px; color: #e1e4e8; line-height: 1.4;">
                                        {settings.EMAIL_SECURITY_NOTICE}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding: 20px; background: rgba(5, 8, 15, 0.6); border-top: 1px solid rgba(255,255,255,0.05); font-size: 11px; color: #6e7681;">
                            {settings.EMAIL_FOOTER_TEXT}
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""

        msg.add_alternative(html_body, subtype="html")

        def _send_email_sync():
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_TLS:
                    server.starttls()
                server.login(
                    settings.SMTP_USER,
                    settings.SMTP_PASSWORD.get_secret_value() if settings.SMTP_PASSWORD else "",
                )
                server.send_message(msg)

        try:
            await asyncio.to_thread(_send_email_sync)
            logger.info("Email OTP sent successfully via SMTP", recipient=recipient)
            return True
        except Exception as e:
            logger.error("Failed to send OTP via SMTP", recipient=recipient, error=str(e))
            return False


def get_otp_channel_strategy() -> OTPChannelStrategy:
    if settings.OTP_CHANNEL == "smtp":
        return SMTPOTPStrategy()
    return ConsoleOTPStrategy()
