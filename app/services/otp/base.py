from abc import ABC, abstractmethod


class OTPChannelStrategy(ABC):
    @abstractmethod
    async def send_otp(self, recipient: str, code: str) -> bool:
        """
        Sends the OTP code to the recipient via the configured channel.
        Returns True if successful, False otherwise.
        """
        pass
