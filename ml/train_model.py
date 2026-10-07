import os
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

print("\n🛡️ SentinelAI - Real CICIDS2017 Threat Detection")
print("=" * 60)

DATA_DIR = "data"

csv_files = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
]

print("\nLoading CICIDS2017 data...")

frames = []

for file in csv_files:
    path = os.path.join(DATA_DIR, file)

    if os.path.exists(path):
        print("Loading:", file)
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)

data = pd.concat(frames, ignore_index=True)

print("\nDataset shape:", data.shape)

data.columns = data.columns.str.strip()

data.replace([np.inf, -np.inf], np.nan, inplace=True)
data.dropna(inplace=True)

data["Label"] = data["Label"].astype(str).str.strip()

data["Attack"] = np.where(
    data["Label"].str.upper() == "BENIGN",
    0,
    1
)

print("\nBenign:", (data["Attack"] == 0).sum())
print("Attacks:", (data["Attack"] == 1).sum())

drop_columns = [
    "Label",
    "Attack",
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp"
]

features = data.drop(
    columns=[c for c in drop_columns if c in data.columns],
    errors="ignore"
)

features = features.apply(
    pd.to_numeric,
    errors="coerce"
)

features.replace([np.inf, -np.inf], np.nan, inplace=True)
features.dropna(axis=1, how="all", inplace=True)
features.fillna(0, inplace=True)

features = features.loc[:, ~features.columns.duplicated()]

X = features
y = data["Attack"]

print("\nFinal feature count:", X.shape[1])

MAX_ROWS = 300000

if len(X) > MAX_ROWS:
    sample_indices = np.random.RandomState(42).choice(
        len(X),
        MAX_ROWS,
        replace=False
    )

    X = X.iloc[sample_indices]
    y = y.iloc[sample_indices]

print("Training rows:", len(X))

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

negative = (y_train == 0).sum()
positive = (y_train == 1).sum()

scale_pos_weight = negative / positive if positive > 0 else 1

print("\nTraining XGBoost...")

model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    random_state=42,
    eval_metric="logloss",
    n_jobs=-1
)

model.fit(X_train, y_train)

prediction = model.predict(X_test)
probability = model.predict_proba(X_test)[:, 1]

print("\n========== MODEL RESULTS ==========")

print(
    classification_report(
        y_test,
        prediction,
        target_names=["Benign", "Attack"]
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, prediction))

print(
    "ROC-AUC:",
    round(roc_auc_score(y_test, probability), 4)
)

print("\nTraining Isolation Forest...")

benign_train = X_train[y_train == 0]

if len(benign_train) > 100000:
    benign_train = benign_train.sample(
        100000,
        random_state=42
    )

anomaly_model = IsolationForest(
    n_estimators=150,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)

anomaly_model.fit(benign_train)

os.makedirs("models", exist_ok=True)

joblib.dump(
    model,
    "models/threat_classifier.pkl"
)

joblib.dump(
    anomaly_model,
    "models/anomaly_detector.pkl"
)

joblib.dump(
    list(X.columns),
    "models/feature_columns.pkl"
)

print("\n✅ Models saved successfully!")
print("\n🛡️ SentinelAI ML engine is ready.")