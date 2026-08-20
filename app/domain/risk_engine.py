import math
from typing import NamedTuple, Optional
import numpy as np
from sklearn.ensemble import IsolationForest

from app.core.config import settings
from app.core.logging import logger


class MLAnomalyDetector:
    """
    Vector #8: Unsupervised Machine Learning Anomaly Detector.
    Uses IsolationForest to detect novel zero-day botnet traffic and behavioral anomalies.
    Evaluates vector features: [user_agent_len, has_sec_ch_ua, is_new_device, geo_velocity, failed_attempts, access_hour]
    """

    def __init__(self):
        # Baseline training set representing normal vs anomalous web traffic requests
        X_train = np.array([
            [110, 1, 0, 0, 0, 14],
            [125, 1, 0, 0, 0, 10],
            [105, 1, 0, 0, 0, 16],
            [95, 1, 0, 0, 0, 9],
            [115, 1, 0, 0, 0, 15],
            [15, 0, 1, 1, 3, 3],  # Anomaly sample 1
            [20, 0, 1, 1, 4, 2],  # Anomaly sample 2
        ])
        self.model = IsolationForest(n_estimators=10, random_state=42)
        self.model.fit(X_train)

    def predict_anomaly_score(
        self,
        user_agent_len: int,
        has_sec_ch_ua: bool,
        is_new_device: bool,
        geo_velocity_alert: bool,
        failed_attempts_count: int,
        access_hour_utc: Optional[int] = None,
    ) -> float:
        features = np.array([
            [
                user_agent_len,
                1 if has_sec_ch_ua else 0,
                1 if is_new_device else 0,
                1 if geo_velocity_alert else 0,
                failed_attempts_count,
                access_hour_utc if access_hour_utc is not None else 12,
            ]
        ])
        raw_score = self.model.decision_function(features)[0]
        # Normalizes raw IsolationForest decision score to range [0.0, 1.0]
        anomaly_index = max(0.0, min(1.0, round((0.15 - raw_score) * 1.5, 2)))
        return anomaly_index


ml_detector = MLAnomalyDetector()


class OTPPolicy(NamedTuple):
    otp_type: str
    length: int
    ttl_seconds: int
    entropy_bits: float
    risk_score: float
    risk_level: str
    requires_2fa_password: bool
    risk_factors: list[str]


class RiskAssessmentEngine:
    """
    Context-Aware Hybrid Multi-Vector Risk-Based Authentication (RBA) Engine.
    Evaluates 8 contextual risk vectors (including Vector #8 Machine Learning Anomaly Detection)
    to calculate risk score R in range [0.0, 1.0] and dynamically scales mathematical OTP entropy H = log2(S^L).
    """

    @staticmethod
    def calculate_entropy(character_set_size: int, length: int) -> float:
        """Calculates mathematical information entropy H = log2(S^L) in bits."""
        return round(length * math.log2(character_set_size), 2)

    def evaluate_request_risk(
        self,
        client_ip: str,
        user_agent: str,
        is_new_device: bool = False,
        geo_velocity_alert: bool = False,
        failed_attempts_count: int = 0,
        access_hour_utc: Optional[int] = None,
        has_sec_ch_ua: bool = True,
    ) -> tuple[float, list[str]]:
        """
        Evaluates 8 contextual risk vectors:
        1. User-Agent Bot / Script Pattern Analysis
        2. IP Address Anomaly & Network Type
        3. Unrecognized Device Footprint
        4. Impossible Geographic Velocity (Geo-Velocity)
        5. Historical Failed OTP Verification Count
        6. Off-Hours Access Pattern Anomaly (Temporal Anomaly)
        7. Missing Client Security Headers (Sec-CH-UA / Accept-Language)
        8. Unsupervised Machine Learning Anomaly Detection (IsolationForest Model)

        Returns (risk_score, risk_factors) where R in range [0.0, 1.0].
        """
        score = 0.0
        factors = []
        ua_lower = (user_agent or "").lower()

        # Vector 1: Bot / Automated Script Detection
        bot_signatures = ["curl", "python", "httpx", "postman", "bot", "spider", "scraper", "headless", "phantom"]
        if any(bot in ua_lower for bot in bot_signatures):
            score += 0.35
            factors.append("automated_bot_user_agent")

        # Vector 2: IP Address Anomaly & Missing Headers
        if client_ip in ("unknown", "127.0.0.1", "0.0.0.0") or not user_agent:
            score += 0.15
            factors.append("suspicious_ip_or_missing_user_agent")

        # Vector 3: Unrecognized Device Footprint
        if is_new_device:
            score += 0.25
            factors.append("unrecognized_new_device")

        # Vector 4: Impossible Geographic Travel Speed (Geo-Velocity)
        if geo_velocity_alert:
            score += 0.40
            factors.append("impossible_geo_velocity_anomaly")

        # Vector 5: Historical Failed OTP Attempts Penalty
        if failed_attempts_count > 0:
            penalty = min(0.30, failed_attempts_count * 0.10)
            score += penalty
            factors.append(f"historical_failed_attempts_{failed_attempts_count}")

        # Vector 6: Temporal Anomaly (Off-hours access window 01:00 - 05:00 UTC)
        if access_hour_utc is not None and (1 <= access_hour_utc <= 5):
            score += 0.15
            factors.append("off_hours_temporal_anomaly")

        # Vector 7: Missing Client Security Headers & Browser Spoofing Inspection
        if "mozilla" in ua_lower:
            missing_headers = []
            if not has_sec_ch_ua:
                missing_headers.append("Sec-CH-UA")
            if missing_headers:
                score += 0.15
                factors.append(f"spoofed_browser_missing_{'_'.join(missing_headers)}")

        # Vector 8: Unsupervised Machine Learning Anomaly Detection (IsolationForest Model)
        ml_anomaly_score = ml_detector.predict_anomaly_score(
            user_agent_len=len(user_agent or ""),
            has_sec_ch_ua=has_sec_ch_ua,
            is_new_device=is_new_device,
            geo_velocity_alert=geo_velocity_alert,
            failed_attempts_count=failed_attempts_count,
            access_hour_utc=access_hour_utc,
        )
        if ml_anomaly_score > 0.20:
            score += ml_anomaly_score * 0.25
            factors.append(f"ml_isolation_forest_anomaly_{ml_anomaly_score}")

        risk_score = round(min(1.0, score), 2)
        return risk_score, factors

    def get_otp_policy(
        self,
        client_ip: str,
        user_agent: str,
        is_new_device: bool = False,
        geo_velocity_alert: bool = False,
        failed_attempts_count: int = 0,
        access_hour_utc: Optional[int] = None,
        has_sec_ch_ua: bool = True,
    ) -> OTPPolicy:
        """
        Determines the dynamic OTP generation policy (Entropy H, TTL, 2FA requirement)
        based on the evaluated risk score R in range [0.0, 1.0].
        """
        risk_score, risk_factors = self.evaluate_request_risk(
            client_ip=client_ip,
            user_agent=user_agent,
            is_new_device=is_new_device,
            geo_velocity_alert=geo_velocity_alert,
            failed_attempts_count=failed_attempts_count,
            access_hour_utc=access_hour_utc,
            has_sec_ch_ua=has_sec_ch_ua,
        )

        if risk_score < 0.30:
            # Low Risk: Numeric OTP (6 digits), H = 19.93 bits, TTL = 300s
            otp_type = "numeric"
            length = 6
            charset_size = 10
            ttl = settings.OTP_EXPIRE_SECONDS
            level = "low"
            requires_2fa = False
        elif risk_score < 0.70:
            # Medium Risk: Alphanumeric Uppercase (8 chars), H = 41.36 bits, TTL = 180s
            otp_type = "alphanumeric_upper"
            length = 8
            charset_size = 36
            ttl = 180
            level = "medium"
            requires_2fa = False
        else:
            # High Risk: Alphanumeric Full (10 chars), H = 59.54 bits, TTL = 120s + Mandatory 2FA Password
            otp_type = "alphanumeric_full"
            length = 10
            charset_size = 62
            ttl = 120
            level = "high"
            requires_2fa = True

        entropy = self.calculate_entropy(charset_size, length)

        return OTPPolicy(
            otp_type=otp_type,
            length=length,
            ttl_seconds=ttl,
            entropy_bits=entropy,
            risk_score=risk_score,
            risk_level=level,
            requires_2fa_password=requires_2fa,
            risk_factors=risk_factors,
        )


risk_engine = RiskAssessmentEngine()
