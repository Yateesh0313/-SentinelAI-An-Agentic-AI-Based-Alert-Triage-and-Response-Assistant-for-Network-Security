"""SentinelAI -- Phase 4: Classical Baseline Model Training.

Trains XGBoost and Random Forest classifiers on the pre-processed NSL-KDD
data from Phase 3, evaluates on the held-out test set, and saves metrics +
trained models for later comparison with the quantum model.

Usage:
    python train_baseline.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import cross_val_score
from xgboost import XGBClassifier

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_ML_DIR = Path(__file__).resolve().parent.parent  # ml/
_PROCESSED_DIR = _ML_DIR / "data" / "processed"
_RESULTS_DIR = _ML_DIR / "results"

# Accuracy thresholds for sanity checks (NSL-KDD KDDTest+ literature range)
_SUSPICIOUSLY_HIGH = 0.95  # > 95% on KDDTest+ suggests data leakage


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_processed() -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Load the pre-processed numpy arrays saved by Phase 3."""
    X_train = np.load(_PROCESSED_DIR / "train_X.npy")
    y_train = np.load(_PROCESSED_DIR / "train_y.npy")
    X_test = np.load(_PROCESSED_DIR / "test_X.npy")
    y_test = np.load(_PROCESSED_DIR / "test_y.npy")
    return X_train, y_train, X_test, y_test


# ---------------------------------------------------------------------------
# Metrics computation (fixed schema for cross-phase comparison)
# ---------------------------------------------------------------------------

def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    model_name: str,
    training_time: float,
    cv_scores: np.ndarray | None = None,
) -> dict[str, Any]:
    """Compute the fixed-schema metrics dict.

    Schema:
        model, accuracy, precision, recall, f1, false_positive_rate,
        confusion_matrix, training_time_seconds, cv_mean, cv_std
    """
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    metrics: dict[str, Any] = {
        "model": model_name,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": round(fpr, 6),
        "confusion_matrix": cm.tolist(),
        "training_time_seconds": round(training_time, 2),
    }

    if cv_scores is not None:
        metrics["cv_mean_accuracy"] = round(float(cv_scores.mean()), 6)
        metrics["cv_std_accuracy"] = round(float(cv_scores.std()), 6)

    return metrics


def print_metrics(metrics: dict[str, Any]) -> None:
    """Pretty-print metrics to the console."""
    cm = metrics["confusion_matrix"]
    print(f"  Accuracy           : {metrics['accuracy']:.4f}")
    print(f"  Precision          : {metrics['precision']:.4f}")
    print(f"  Recall             : {metrics['recall']:.4f}")
    print(f"  F1 Score           : {metrics['f1']:.4f}")
    print(f"  False Positive Rate: {metrics['false_positive_rate']:.4f}")
    if "cv_mean_accuracy" in metrics:
        print(f"  CV Accuracy (5-fold): {metrics['cv_mean_accuracy']:.4f} "
              f"+/- {metrics['cv_std_accuracy']:.4f}")
    print(f"  Training Time      : {metrics['training_time_seconds']:.2f}s")
    print(f"  Confusion Matrix   :")
    print(f"    TN={cm[0][0]:>6}  FP={cm[0][1]:>6}")
    print(f"    FN={cm[1][0]:>6}  TP={cm[1][1]:>6}")


def sanity_check(metrics: dict[str, Any], model_name: str) -> None:
    """Flag suspiciously high accuracy that might indicate data leakage."""
    acc = metrics["accuracy"]
    if acc > _SUSPICIOUSLY_HIGH:
        print()
        print(f"  [WARNING] {model_name} test accuracy = {acc:.4f}")
        print(f"  This is above {_SUSPICIOUSLY_HIGH:.0%}, which is unusually high")
        print(f"  for NSL-KDD KDDTest+ (published baselines: ~78-85%).")
        print(f"  Possible causes: scaler/encoder fit on test, or data leakage.")
        print(f"  Flagging for review -- not necessarily a bug, but verify upstream.")


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------

def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> dict[str, Any]:
    """Train an XGBoost classifier and evaluate on test."""
    print("=" * 64)
    print("  XGBoost Classifier")
    print("=" * 64)

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    # 5-fold cross-validation on training set
    print("  Running 5-fold cross-validation on training set ...")
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy", n_jobs=-1)
    print(f"  CV scores: {[round(s, 4) for s in cv_scores]}")
    print(f"  CV mean: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")
    print()

    # Train on full training set
    print("  Training on full training set ...")
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    train_time = time.perf_counter() - t0
    print(f"  Done in {train_time:.2f}s")
    print()

    # Evaluate on test set
    print("  Test set evaluation:")
    y_pred = model.predict(X_test)
    metrics = compute_metrics(y_test, y_pred, "xgboost", train_time, cv_scores)
    print_metrics(metrics)
    sanity_check(metrics, "XGBoost")

    # Save model
    model_path = _RESULTS_DIR / "classical_baseline_model.joblib"
    joblib.dump(model, model_path)
    print(f"\n  Model saved -> {model_path.name}")

    # Save metrics
    metrics_path = _RESULTS_DIR / "classical_baseline_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics saved -> {metrics_path.name}")

    return metrics


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> dict[str, Any]:
    """Train a Random Forest classifier and evaluate on test."""
    print()
    print("=" * 64)
    print("  Random Forest Classifier")
    print("=" * 64)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )

    # 5-fold cross-validation on training set
    print("  Running 5-fold cross-validation on training set ...")
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy", n_jobs=-1)
    print(f"  CV scores: {[round(s, 4) for s in cv_scores]}")
    print(f"  CV mean: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")
    print()

    # Train on full training set
    print("  Training on full training set ...")
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    train_time = time.perf_counter() - t0
    print(f"  Done in {train_time:.2f}s")
    print()

    # Evaluate on test set
    print("  Test set evaluation:")
    y_pred = model.predict(X_test)
    metrics = compute_metrics(y_test, y_pred, "random_forest", train_time, cv_scores)
    print_metrics(metrics)
    sanity_check(metrics, "Random Forest")

    # Save model
    model_path = _RESULTS_DIR / "classical_rf_model.joblib"
    joblib.dump(model, model_path)
    print(f"\n  Model saved -> {model_path.name}")

    # Save metrics
    metrics_path = _RESULTS_DIR / "classical_rf_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics saved -> {metrics_path.name}")

    return metrics


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Train and evaluate both classical baselines."""
    print()
    print("+" + "=" * 62 + "+")
    print("|  SentinelAI -- Phase 4: Classical Baseline Training" + " " * 10 + "|")
    print("+" + "=" * 62 + "+")
    print()

    # Load data
    print("Loading pre-processed data from ml/data/processed/ ...")
    X_train, y_train, X_test, y_test = load_processed()
    print(f"  X_train: {X_train.shape}  y_train: {y_train.shape}")
    print(f"  X_test:  {X_test.shape}  y_test:  {y_test.shape}")
    print()

    # Train both models
    xgb_metrics = train_xgboost(X_train, y_train, X_test, y_test)
    rf_metrics = train_random_forest(X_train, y_train, X_test, y_test)

    # Summary comparison
    print()
    print("=" * 64)
    print("  COMPARISON SUMMARY")
    print("=" * 64)
    print(f"  {'Metric':<22} {'XGBoost':>10} {'RandomForest':>14}")
    print(f"  {'-'*22} {'-'*10} {'-'*14}")
    for key in ["accuracy", "precision", "recall", "f1", "false_positive_rate"]:
        xv = xgb_metrics[key]
        rv = rf_metrics[key]
        print(f"  {key:<22} {xv:>10.4f} {rv:>14.4f}")
    print(f"  {'training_time (s)':<22} {xgb_metrics['training_time_seconds']:>10.2f} "
          f"{rf_metrics['training_time_seconds']:>14.2f}")
    print()
    print("  All results saved to ml/results/")
    print("+" + "=" * 62 + "+")


if __name__ == "__main__":
    main()
