from datetime import datetime


def investigate_threat(
    prediction,
    threat_probability,
    anomaly,
    risk_score,
    severity,
    top_risk_factors
):
    """
    Generate an investigation report for a detected security event.
    """

    if severity == "CRITICAL":
        priority = "IMMEDIATE INVESTIGATION"
    elif severity == "HIGH":
        priority = "HIGH PRIORITY INVESTIGATION"
    elif severity == "MEDIUM":
        priority = "REVIEW REQUIRED"
    else:
        priority = "MONITOR"

    evidence = []

    if prediction == "ATTACK":
        evidence.append(
            "ML classifier identified the network flow as a potential attack."
        )

    if anomaly == "ANOMALOUS":
        evidence.append(
            "Isolation Forest detected abnormal behavior."
        )

    for factor in top_risk_factors[:5]:
        if factor["impact"] > 0:
            evidence.append(
                f'{factor["feature"]} increased the threat score.'
            )

    recommendations = [
        "Review the source and destination of the network flow.",
        "Check whether similar events occurred recently.",
        "Investigate unusual traffic patterns and connection frequency.",
        "Correlate this event with other security alerts.",
        "Escalate the incident if malicious activity is confirmed."
    ]

    return {
        "investigation_id": (
            "INC-" +
            datetime.now().strftime("%Y%m%d%H%M%S")
        ),
        "timestamp": datetime.now().isoformat(),
        "prediction": prediction,
        "threat_probability": threat_probability,
        "anomaly": anomaly,
        "risk_score": risk_score,
        "severity": severity,
        "priority": priority,
        "evidence": evidence,
        "recommended_actions": recommendations,
        "status": "OPEN"
    }


if __name__ == "__main__":

    result = investigate_threat(
        prediction="ATTACK",
        threat_probability=94.5,
        anomaly="ANOMALOUS",
        risk_score=91.2,
        severity="CRITICAL",
        top_risk_factors=[
            {
                "feature": "Destination Port",
                "impact": 2.31
            },
            {
                "feature": "Flow Duration",
                "impact": 1.82
            }
        ]
    )

    print("\n🕵️ SentinelAI Threat Investigation")
    print("=" * 50)

    for key, value in result.items():
        print(f"\n{key}:")
        print(value)