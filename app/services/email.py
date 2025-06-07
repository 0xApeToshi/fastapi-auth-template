from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class EmailService(ABC):
    """
    Abstract base class for email service implementations.
    This allows for easy swapping of email providers (SendGrid, AWS SES, etc.)
    """

    @abstractmethod
    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        from_email: Optional[str] = None,
    ) -> bool:
        """
        Send an email.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML content of the email
            text_content: Plain text content (optional)
            from_email: Sender email address (optional, uses default if not provided)

        Returns:
            True if email was sent successfully
        """
        pass

    @abstractmethod
    async def send_bulk_email(
        self,
        recipients: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        from_email: Optional[str] = None,
    ) -> Dict[str, bool]:
        """
        Send bulk emails.

        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            html_content: HTML content of the email
            text_content: Plain text content (optional)
            from_email: Sender email address (optional)

        Returns:
            Dictionary mapping email addresses to success status
        """
        pass

    async def send_password_reset_email(
        self, to_email: str, reset_code: str, expires_in_minutes: int = 30
    ) -> bool:
        """
        Send password reset email with PIN code.

        Args:
            to_email: Recipient email address
            reset_code: 6-digit reset code
            expires_in_minutes: How long the code is valid

        Returns:
            True if email was sent successfully
        """
        subject = "Password Reset Code"

        html_content = f"""
        <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>You have requested to reset your password.</p>
                <p>Your reset code is: <strong>{reset_code}</strong></p>
                <p>This code will expire in {expires_in_minutes} minutes.</p>
                <p>If you did not request this reset, please ignore this email.</p>
                <br>
                <p>Best regards,<br>Your Security Team</p>
            </body>
        </html>
        """

        text_content = f"""
        Password Reset Request
        
        You have requested to reset your password.
        Your reset code is: {reset_code}
        
        This code will expire in {expires_in_minutes} minutes.
        
        If you did not request this reset, please ignore this email.
        
        Best regards,
        Your Security Team
        """

        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
        )


class MockEmailService(EmailService):
    """
    Mock implementation of EmailService for development/testing.
    Logs emails instead of sending them.
    """

    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        from_email: Optional[str] = None,
    ) -> bool:
        """Mock email sending - just logs the email."""
        print(f"[MOCK EMAIL] To: {to_email}")
        print(f"[MOCK EMAIL] Subject: {subject}")
        print(f"[MOCK EMAIL] From: {from_email or 'default@example.com'}")
        if text_content:
            print(f"[MOCK EMAIL] Content: {text_content[:200]}...")
        return True

    async def send_bulk_email(
        self,
        recipients: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        from_email: Optional[str] = None,
    ) -> Dict[str, bool]:
        """Mock bulk email sending."""
        results = {}
        for recipient in recipients:
            results[recipient] = await self.send_email(
                recipient, subject, html_content, text_content, from_email
            )
        return results
