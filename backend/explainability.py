import joblib
import pandas as pd
import shap

MODEL_PATH = "models/threat_classifier.pkl"
FEATURE_PATH = "models/feature_columns.pkl"

model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURE_PATH)


def explain_prediction(input_data):

    df = pd.DataFrame(
        [input_data],
        columns=feature_columns
    )

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(df)

    values = shap_values[0]

    explanation = []

    for feature, value in zip(feature_columns, values):
        explanation.append({
            "feature": feature,
            "impact": float(value)
        })

    explanation.sort(
        key=lambda x: abs(x["impact"]),
        reverse=True
    )

    return explanation[:10]


if __name__ == "__main__":

    sample = [0] * len(feature_columns)

    result = explain_prediction(sample)

    print("\n🧠 SentinelAI - SHAP Explanation")
    print("=" * 50)

    for item in result:
        print(
            item["feature"],
            "→",
            round(item["impact"], 4)
        )