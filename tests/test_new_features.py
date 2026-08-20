import pytest
from app.domain.risk_engine import risk_engine, ml_detector
from app.core.json_engine import JSONEngine

def test_ml_anomaly_detector_vector_8():
    # Normal user traffic baseline test
    normal_score = ml_detector.predict_anomaly_score(
        user_agent_len=110,
        has_sec_ch_ua=True,
        is_new_device=False,
        geo_velocity_alert=False,
        failed_attempts_count=0,
        access_hour_utc=14,
    )
    assert normal_score < 0.30

    # Anomalous botnet traffic test
    anomalous_score = ml_detector.predict_anomaly_score(
        user_agent_len=15,
        has_sec_ch_ua=False,
        is_new_device=True,
        geo_velocity_alert=True,
        failed_attempts_count=3,
        access_hour_utc=3,
    )
    assert anomalous_score > 0.30

def test_hybrid_risk_assessment_with_vector_8():
    policy = risk_engine.get_otp_policy(
        client_ip="192.168.1.50",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        is_new_device=True,
        geo_velocity_alert=True,
        failed_attempts_count=2,
        access_hour_utc=2,
        has_sec_ch_ua=False,
    )
    assert policy.risk_level == "high"
    assert "unrecognized_new_device" in policy.risk_factors

def test_json_engine_msgspec_vs_pydantic():
    data = {"key": "value", "numbers": [1, 2, 3]}
    
    # Test msgspec
    engine_msg = JSONEngine(engine_name="msgspec")
    encoded_msg = engine_msg.encode(data)
    decoded_msg = engine_msg.decode(encoded_msg)
    assert decoded_msg == data

    # Test pydantic fallback
    engine_pyd = JSONEngine(engine_name="pydantic")
    encoded_pyd = engine_pyd.encode(data)
    decoded_pyd = engine_pyd.decode(encoded_pyd)
    assert decoded_pyd == data
