import numpy as np


def calculate_risk(threat_probability, anomaly_score):
    """
    Calculate SentinelAI risk score from 0-100.
    """

    threat_probability = float(threat_probability)

    # Convert Isolation Forest score into anomaly percentage
    anomaly_score = float(anomaly_score)

    anomaly_risk = min(max(anomaly_score, 0), 1)

    # Weighted risk calculation
    risk_score = (
        (threat_probability * 70) +
        (anomaly_risk * 30)
    )

    risk_score = round(min(max(risk_score, 0), 100), 2)

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "severity": severity
    }


if __name__ == "__main__":

    result = calculate_risk(
        threat_probability=0.92,
        anomaly_score=0.80
    )

    print("\n🛡️ SentinelAI Risk Engine")
    print("=" * 40)
    print("Risk Score:", result["risk_score"])
    print("Severity:", result["severity"])