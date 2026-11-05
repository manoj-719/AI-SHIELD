
import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = PROJECT_ROOT / "ml" / "employee_dataset.csv"
MODEL_DIR = PROJECT_ROOT / "ml" / "saved_model"
MODEL_FILE = MODEL_DIR / "isolation_forest.pkl"
THRESHOLD_FILE = MODEL_DIR / "anomaly_threshold.txt"

# Load dataset
dataset = pd.read_csv(DATASET_FILE)

# Separate labels and features
labels = dataset["simulated_suspicious"]

features = dataset.drop(
    columns=["simulated_suspicious", "activity_pattern"],
    errors="ignore"
)

# Split dataset into training and testing
X_train, X_test, y_train, y_test = train_test_split(
    features,
    labels,
    test_size=0.20,
    random_state=42,
    stratify=labels
)

# Train only on normal employee activities
normal_train = X_train[y_train == 0]

# Split normal data for threshold calibration
train_data, calibration_data = train_test_split(
    normal_train,
    test_size=0.20,
    random_state=42
)

# Create Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42
)

# Train model
model.fit(train_data)

# Calibrate threshold using normal activities
calibration_scores = model.score_samples(calibration_data)

threshold = np.quantile(calibration_scores, 0.10)

# Evaluate on unseen test data
test_scores = model.score_samples(X_test)

predicted_labels = (test_scores < threshold).astype(int)

# Calculate accuracy
accuracy = accuracy_score(y_test, predicted_labels)

print("\n========== AI SHIELD MODEL EVALUATION ==========")

print(f"\nModel Accuracy: {accuracy * 100:.2f}%")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predicted_labels))

print("\nClassification Report:")
print(classification_report(
    y_test,
    predicted_labels,
    target_names=["Normal", "Suspicious"],
    zero_division=0
))

# Threshold comparison on test data
print("\n========== THRESHOLD COMPARISON ==========")

for percentile in [1, 2, 5, 10, 15, 20]:
    threshold_test = np.quantile(
        calibration_scores,
        percentile / 100
    )

    predictions = (
        test_scores < threshold_test
    ).astype(int)

    print(
        f"Threshold percentile: {percentile}% | "
        f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}% | "
        f"Suspicious caught: "
        f"{((predictions == 1) & (y_test.to_numpy() == 1)).sum()} "
        f"out of {(y_test == 1).sum()}"
    )

print("\n============================================")

# Save model and threshold
MODEL_DIR.mkdir(parents=True, exist_ok=True)

joblib.dump(model, MODEL_FILE)

with open(THRESHOLD_FILE, "w", encoding="utf-8") as file:
    file.write(str(threshold))

print("\nModel training completed!")
print("Model saved to:", MODEL_FILE)
print("Threshold saved to:", THRESHOLD_FILE)
