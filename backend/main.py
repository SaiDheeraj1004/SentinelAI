from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
import numpy as np
import shap

from backend.risk_engine import calculate_risk
from backend.investigation_engine import investigate_threat
from backend.threat_graph import build_threat_graph
from backend.database import SessionLocal, Incident, create_tables
from backend.ai_agent import investigation_agent

app = FastAPI(
    title="SentinelAI",
    description="Intelligent Cyber Threat Detection & Investigation Platform",
    version="1.0"
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])



# Create database tables
create_tables()


# Load models
model = joblib.load("models/threat_classifier.pkl")
anomaly_model = joblib.load("models/anomaly_detector.pkl")
feature_columns = joblib.load("models/feature_columns.pkl")

explainer = shap.TreeExplainer(model)


@app.get("/")
def home():
    return {
        "system": "SentinelAI",
        "status": "online",
        "message": "Cyber Threat Detection API is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model": "XGBoost",
        "anomaly_detector": "Isolation Forest",
        "explainability": "SHAP",
        "investigation": "Enabled",
        "threat_graph": "Enabled",
        "database": "PostgreSQL"
    }


@app.get("/incidents")
def get_incidents():

    db = SessionLocal()

    try:

        incidents = (
            db.query(Incident)
            .order_by(Incident.id.desc())
            .all()
        )

        results = []

        for incident in incidents:

            results.append({
                "id": incident.id,
                "timestamp": incident.timestamp,
                "prediction": incident.prediction,
                "threat_probability": incident.threat_probability,
                "anomaly": incident.anomaly,
                "risk_score": incident.risk_score,
                "severity": incident.severity,
                "priority": incident.priority,
                "status": incident.status,
                "source_ip": incident.source_ip,
                "destination_ip": incident.destination_ip,
                "destination_port": incident.destination_port,
                "risk_factors": incident.risk_factors,
                "investigation": incident.investigation,
                "threat_graph": incident.threat_graph
            })

        return {
            "total_incidents": len(results),
            "incidents": results
        }

    finally:

        db.close()


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            return {
                "error": "Incident not found"
            }

        return {
            "id": incident.id,
            "timestamp": incident.timestamp,
            "prediction": incident.prediction,
            "threat_probability": incident.threat_probability,
            "anomaly": incident.anomaly,
            "risk_score": incident.risk_score,
            "severity": incident.severity,
            "priority": incident.priority,
            "status": incident.status,
            "source_ip": incident.source_ip,
            "destination_ip": incident.destination_ip,
            "destination_port": incident.destination_port,
            "risk_factors": incident.risk_factors,
            "investigation": incident.investigation,
            "threat_graph": incident.threat_graph
        }

    finally:

        db.close()

@app.post("/predict")
def predict(data: dict):

    input_data = []

    for feature in feature_columns:
        input_data.append(
            float(data.get(feature, 0))
        )

    X = pd.DataFrame(
        [input_data],
        columns=feature_columns
    )

    # Network information
    source_ip = data.get(
        "source_ip",
        data.get("Source IP", "Unknown")
    )

    destination_ip = data.get(
        "destination_ip",
        data.get("Destination IP", "Unknown")
    )

    destination_port = int(
        data.get(
            "destination_port",
            data.get("Destination Port", 0)
        )
    )

    # XGBoost prediction
    probability = float(
        model.predict_proba(X)[0][1]
    )

    prediction = int(
        model.predict(X)[0]
    )

    # Isolation Forest
    anomaly_prediction = anomaly_model.predict(X)[0]

    anomaly_score_raw = -anomaly_model.decision_function(X)[0]

    anomaly_score = float(
        np.clip(
            anomaly_score_raw,
            0,
            1
        )
    )

    # Risk score
    risk = calculate_risk(
        probability,
        anomaly_score
    )

    # SHAP explanation
    shap_values = explainer.shap_values(X)[0]

    explanation = []

    for feature, value in zip(
        feature_columns,
        shap_values
    ):

        explanation.append({
            "feature": feature,
            "impact": round(
                float(value),
                4
            )
        })

    explanation.sort(
        key=lambda x: abs(x["impact"]),
        reverse=True
    )

    explanation = explanation[:10]

    # Prediction label
    prediction_label = (
        "ATTACK"
        if prediction == 1
        else "BENIGN"
    )

    # Anomaly label
    anomaly_label = (
        "ANOMALOUS"
        if anomaly_prediction == -1
        else "NORMAL"
    )

    # Threat probability
    threat_probability = round(
        probability * 100,
        2
    )

    # Threat Investigation
    investigation = investigate_threat(
        prediction=prediction_label,
        threat_probability=threat_probability,
        anomaly=anomaly_label,
        risk_score=risk["risk_score"],
        severity=risk["severity"],
        top_risk_factors=explanation
    )

    # Threat Graph
    threat_graph = build_threat_graph(
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        prediction=prediction_label,
        severity=risk["severity"]
    )

    # Save incident to PostgreSQL
    db = SessionLocal()

    try:

        incident = Incident(
            prediction=prediction_label,
            threat_probability=threat_probability,
            anomaly=anomaly_label,
            risk_score=risk["risk_score"],
            severity=risk["severity"],
            priority=investigation["priority"],
            status=investigation["status"],
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            risk_factors=explanation,
            investigation=investigation,
            threat_graph=threat_graph
        )

        db.add(incident)

        db.commit()

        db.refresh(incident)

        incident_id = incident.id

    finally:

        db.close()

    return {
        "incident_id": incident_id,
        "prediction": prediction_label,
        "threat_probability": threat_probability,
        "anomaly": anomaly_label,
        "risk_score": risk["risk_score"],
        "severity": risk["severity"],
        "top_risk_factors": explanation,
        "investigation": investigation,
        "threat_graph": threat_graph,
        "database": "Incident saved successfully"
    }