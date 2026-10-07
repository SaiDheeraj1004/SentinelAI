import os
from typing import TypedDict

from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI


load_dotenv()


class InvestigationState(TypedDict):
    incident: dict
    analysis: str
    recommendations: list
    status: str


llm = ChatGoogleGenerativeAI(
    model="gemini-3.8-flash",
    temperature=0.2,
    google_api_key=os.getenv("GOOGLE_API_KEY"),
    timeout=30,
    max_retries=0
)


def get_response_text(response):
    if isinstance(response.content, str):
        return response.content

    if isinstance(response.content, list):
        texts = []

        for item in response.content:
            if isinstance(item, dict) and "text" in item:
                texts.append(item["text"])

        return "\n".join(texts)

    return str(response.content)


def fallback_analysis(incident):
    prediction = incident.get("prediction")
    probability = incident.get("threat_probability")
    anomaly = incident.get("anomaly")
    risk = incident.get("risk_score")
    severity = incident.get("severity")

    if prediction == "ATTACK":
        analysis = (
            f"The ML classifier identified this event as a potential attack "
            f"with a threat probability of {probability}%. "
        )
    else:
        analysis = (
            f"The ML classifier currently identifies this event as benign "
            f"with a threat probability of {probability}%. "
        )

    analysis += (
        f"The event has a risk score of {risk}/100 and a severity of "
        f"{severity}. Isolation Forest classified the behavior as "
        f"{anomaly}. The source and destination should be reviewed and "
        f"the event should be correlated with other security alerts "
        f"before making a final security decision."
    )

    return analysis


def fallback_recommendations(incident):
    return [
        "Review the source and destination IP addresses and destination port.",
        "Check whether similar traffic patterns occurred recently.",
        "Correlate the event with other security alerts and logs.",
        "Escalate the incident if malicious activity is confirmed."
    ]


def analyze_incident(state: InvestigationState):

    incident = state["incident"]

    prompt = f"""
You are SentinelAI, a cybersecurity investigation assistant.

Analyze this security incident:

Prediction: {incident.get("prediction")}
Threat Probability: {incident.get("threat_probability")}%
Anomaly: {incident.get("anomaly")}
Risk Score: {incident.get("risk_score")}/100
Severity: {incident.get("severity")}
Source IP: {incident.get("source_ip", "Unknown")}
Destination IP: {incident.get("destination_ip", "Unknown")}
Destination Port: {incident.get("destination_port", "Unknown")}

Provide a concise cybersecurity investigation analysis.

Explain:
1. Why the event may be suspicious.
2. What the risk level means.
3. What an analyst should investigate next.

Do not claim certainty when evidence is insufficient.
"""

    try:
        response = llm.invoke(prompt)

        return {
            "analysis": get_response_text(response)
        }

    except Exception as error:

        print(
            f"Gemini temporarily unavailable. "
            f"Using fallback investigation: {error}"
        )

        return {
            "analysis": fallback_analysis(incident)
        }


def generate_recommendations(state: InvestigationState):

    incident = state["incident"]

    prompt = f"""
You are a cybersecurity incident response assistant.

Based on this incident:

Prediction: {incident.get("prediction")}
Threat Probability: {incident.get("threat_probability")}%
Anomaly: {incident.get("anomaly")}
Risk Score: {incident.get("risk_score")}/100
Severity: {incident.get("severity")}

Give exactly 4 practical cybersecurity investigation or response recommendations.

Return each recommendation on a separate line.
Do not add an introduction.
"""

    try:
        response = llm.invoke(prompt)

        text = get_response_text(response)

        recommendations = [
            line.strip()
            for line in text.split("\n")
            if line.strip()
        ]

        return {
            "recommendations": recommendations[:4]
        }

    except Exception as error:

        print(
            f"Gemini temporarily unavailable. "
            f"Using fallback recommendations: {error}"
        )

        return {
            "recommendations": fallback_recommendations(incident)
        }


def finalize_investigation(state: InvestigationState):

    return {
        "status": "INVESTIGATION_COMPLETE"
    }


workflow = StateGraph(InvestigationState)

workflow.add_node(
    "analyze_incident",
    analyze_incident
)

workflow.add_node(
    "generate_recommendations",
    generate_recommendations
)

workflow.add_node(
    "finalize_investigation",
    finalize_investigation
)

workflow.set_entry_point(
    "analyze_incident"
)

workflow.add_edge(
    "analyze_incident",
    "generate_recommendations"
)

workflow.add_edge(
    "generate_recommendations",
    "finalize_investigation"
)

workflow.add_edge(
    "finalize_investigation",
    END
)

investigation_agent = workflow.compile()
