import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = PROJECT_ROOT / "ml" / "employee_dataset.csv"
MODEL_DIR = PROJECT_ROOT / "ml" / "saved_model"
MODEL_FILE = MODEL_DIR / "isolation_forest.pkl"
THRESHOLD_FILE = MODEL_DIR / "anomaly_threshold.txt"

# Load dataset
dataset = pd.read_csv(DATASET_FILE)

# Separate labels from input features
labels = dataset["simulated_suspicious"]
features = dataset.drop(columns=["simulated_suspicious"])

# Keep only normal events for model training
normal_features = features[labels == 0]

# Split normal events into training and calibration sets
train_data, calibration_data = train_test_split(
    normal_features,
    test_size=0.20,
    random_state=42
)

# Create Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42
)

# Train the model
model.fit(train_data)

# Calibrate threshold using normal activities
calibration_scores = model.score_samples(calibration_data)

# Lower scores indicate more unusual activities
import numpy as np

threshold = np.quantile(calibration_scores, 0.10)


all_scores = model.score_samples(features)

import numpy as np

print("\nTHRESHOLD COMPARISON")

for percentile in [1, 2, 5, 10, 15, 20]:
    threshold_test = np.quantile(
        calibration_scores,
        percentile / 100
    )

    predictions_test = (
        all_scores < threshold_test
    ).astype(int)

    print(
        f"Threshold percentile: {percentile}% | "
        f"Detected: {predictions_test.sum()} | "
        f"Suspicious caught: "
        f"{((predictions_test == 1) & (labels.to_numpy() == 1)).sum()}"
    )

# Diagnostic: compare scores by actual class
score_data = pd.DataFrame({
    "anomaly_score": all_scores,
    "actual_label": labels.to_numpy()
})

print("\n========== ANOMALY SCORE DIAGNOSTIC ==========")

print(
    score_data.groupby("actual_label")["anomaly_score"]
    .agg(["count", "mean", "min", "max", "median"])
)

print("==============================================")

predicted_labels = (all_scores < threshold).astype(int)

# Evaluate results
print("\nAnomaly threshold:", threshold)

print("\nNormal predictions:", (predicted_labels == 0).sum())
print("Anomaly predictions:", (predicted_labels == 1).sum())

print("\nConfusion Matrix:")
print(confusion_matrix(labels, predicted_labels))

print("\nClassification Report:")
print(classification_report(
    labels,
    predicted_labels,
    target_names=["Normal", "Suspicious"],
    zero_division=0
))

# Save model and threshold
MODEL_DIR.mkdir(parents=True, exist_ok=True)

joblib.dump(model, MODEL_FILE)

with open(THRESHOLD_FILE, "w", encoding="utf-8") as file:
    file.write(str(threshold))

print("\nModel training completed!")
print("Model saved to:", MODEL_FILE)
print("Threshold saved to:", THRESHOLD_FILE)