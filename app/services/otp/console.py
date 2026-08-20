from app.core.logging import logger
from app.services.otp.base import OTPChannelStrategy


class ConsoleOTPStrategy(OTPChannelStrategy):
    """
    Console/Mock OTP delivery strategy for development and testing.
    Prints the OTP code to log (using RedactPIIProcessor in non-dev,
    or explicit dev output).
    """

    async def send_otp(self, recipient: str, code: str) -> bool:
        logger.info(
            "================ [DEV OTP DELIVERY] ================",
            recipient=recipient,
            otp=code,
        )
        return True
