"""SentinelAI -- Phase 5: Quantum Variational Classifier Training.

Trains a PennyLane variational quantum classifier on PCA-reduced NSL-KDD
data and evaluates on the SAME test set used by the classical baselines
in Phase 4, using the identical metrics schema for direct comparison.

Key design decisions documented for honest reporting:
  - PCA reduces 122 features down to 4 components (4 qubits).
  - Training uses a SUBSAMPLE of 1000 examples (simulator constraint).
  - Evaluation uses the FULL test set (22544 examples) -- same as Phase 4.
  - This asymmetry is standard practice in quantum-classical comparison
    studies and is explicitly documented in the results JSON.

Usage:
    python train_quantum.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pennylane as qml
from sklearn.decomposition import PCA
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_ML_DIR = Path(__file__).resolve().parent.parent  # ml/
_PROCESSED_DIR = _ML_DIR / "data" / "processed"
_RESULTS_DIR = _ML_DIR / "results"

# ---------------------------------------------------------------------------
# Hyperparameters
# ---------------------------------------------------------------------------

N_QUBITS = 4            # number of qubits = number of PCA components
N_LAYERS = 2            # variational circuit depth
N_EPOCHS = 25           # training epochs
BATCH_SIZE = 25         # mini-batch size
LEARNING_RATE = 0.01    # Adam learning rate
TRAIN_SUBSAMPLE = 500   # quantum training subsample size
RANDOM_SEED = 42


# ---------------------------------------------------------------------------
# Data loading + PCA
# ---------------------------------------------------------------------------

def load_and_reduce() -> tuple[
    np.ndarray, np.ndarray, np.ndarray, np.ndarray, PCA
]:
    """Load processed arrays and apply PCA to reduce to N_QUBITS features.

    PCA is fit on train only, applied to both train and test.

    Returns
    -------
    X_train_pca, y_train, X_test_pca, y_test, pca
    """
    X_train_full = np.load(_PROCESSED_DIR / "train_X.npy")
    y_train = np.load(_PROCESSED_DIR / "train_y.npy")
    X_test_full = np.load(_PROCESSED_DIR / "test_X.npy")
    y_test = np.load(_PROCESSED_DIR / "test_y.npy")

    print(f"  Raw shapes: X_train={X_train_full.shape}, X_test={X_test_full.shape}")

    # PCA: fit on train, transform both
    pca = PCA(n_components=N_QUBITS, random_state=RANDOM_SEED)
    X_train_pca = pca.fit_transform(X_train_full)
    X_test_pca = pca.transform(X_test_full)

    explained = pca.explained_variance_ratio_
    total_explained = sum(explained)
    print(f"  PCA: {X_train_full.shape[1]} features -> {N_QUBITS} components")
    print(f"  Explained variance per component: {[round(float(v), 4) for v in explained]}")
    print(f"  Total explained variance: {total_explained:.4f} ({total_explained*100:.1f}%)")

    # Normalize PCA outputs to [-pi, pi] for angle encoding
    # Use min-max scaling per feature based on TRAIN statistics
    train_min = X_train_pca.min(axis=0)
    train_max = X_train_pca.max(axis=0)
    scale = train_max - train_min
    scale[scale == 0] = 1.0  # avoid division by zero

    X_train_pca = (X_train_pca - train_min) / scale * 2 * np.pi - np.pi
    X_test_pca = (X_test_pca - train_min) / scale * 2 * np.pi - np.pi

    return X_train_pca, y_train, X_test_pca, y_test, pca


def subsample_train(
    X: np.ndarray, y: np.ndarray, n: int
) -> tuple[np.ndarray, np.ndarray]:
    """Stratified subsample of training data for quantum simulator speed."""
    rng = np.random.RandomState(RANDOM_SEED)
    # Stratified: keep class ratio
    idx_0 = np.where(y == 0)[0]
    idx_1 = np.where(y == 1)[0]
    ratio_1 = len(idx_1) / len(y)
    n_1 = int(n * ratio_1)
    n_0 = n - n_1

    chosen_0 = rng.choice(idx_0, size=min(n_0, len(idx_0)), replace=False)
    chosen_1 = rng.choice(idx_1, size=min(n_1, len(idx_1)), replace=False)
    chosen = np.concatenate([chosen_0, chosen_1])
    rng.shuffle(chosen)

    return X[chosen], y[chosen]


# ---------------------------------------------------------------------------
# Quantum circuit
# ---------------------------------------------------------------------------

dev = qml.device("default.qubit", wires=N_QUBITS)


@qml.qnode(dev, interface="autograd")
def quantum_circuit(inputs, weights):
    """Variational quantum classifier circuit.

    - Angle encoding: RX rotation per qubit with input features.
    - StronglyEntanglingLayers for variational part.
    - Measurement: expectation value of PauliZ on qubit 0.
    """
    # Angle encoding
    for i in range(N_QUBITS):
        qml.RX(inputs[i], wires=i)

    # Variational layers
    qml.StronglyEntanglingLayers(weights, wires=range(N_QUBITS))

    # Measurement
    return qml.expval(qml.PauliZ(0))


def predict_single(x, weights):
    """Predict class for a single sample. Returns 0 or 1."""
    output = quantum_circuit(x, weights)
    return 1 if output < 0 else 0


def predict_batch(X, weights):
    """Predict classes for a batch of samples."""
    return np.array([predict_single(x, weights) for x in X])


# ---------------------------------------------------------------------------
# Cost function
# ---------------------------------------------------------------------------

def cost(weights, X_batch, y_batch):
    """Binary cross-entropy-like cost using quantum circuit outputs.

    Maps circuit output from [-1, 1] to probability via (1 - output) / 2,
    then computes mean squared error against labels.
    """
    total_loss = 0.0
    for x, y in zip(X_batch, y_batch):
        output = quantum_circuit(x, weights)
        # Map: output=+1 -> prob=0 (normal), output=-1 -> prob=1 (anomaly)
        prob = (1 - output) / 2
        total_loss += (prob - y) ** 2
    return total_loss / len(y_batch)


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------

def train_quantum(
    X_train: np.ndarray, y_train: np.ndarray
) -> tuple[np.ndarray, float]:
    """Train the variational quantum classifier.

    Returns
    -------
    weights : np.ndarray
        Trained circuit parameters.
    train_time : float
        Wall-clock training time in seconds.
    """
    # Initialize weights
    rng = np.random.RandomState(RANDOM_SEED)
    weight_shape = qml.StronglyEntanglingLayers.shape(
        n_layers=N_LAYERS, n_wires=N_QUBITS
    )
    weights = rng.uniform(-np.pi, np.pi, size=weight_shape)
    weights = qml.numpy.array(weights, requires_grad=True)

    opt = qml.AdamOptimizer(stepsize=LEARNING_RATE)

    n_samples = len(X_train)
    n_batches = max(1, n_samples // BATCH_SIZE)

    print(f"  Training: {N_EPOCHS} epochs, {n_samples} samples, "
          f"batch_size={BATCH_SIZE}, {n_batches} batches/epoch")
    print()

    t0 = time.perf_counter()

    for epoch in range(N_EPOCHS):
        # Shuffle
        perm = rng.permutation(n_samples)
        X_shuffled = X_train[perm]
        y_shuffled = y_train[perm]

        epoch_loss = 0.0
        for b in range(n_batches):
            start = b * BATCH_SIZE
            end = min(start + BATCH_SIZE, n_samples)
            X_batch = X_shuffled[start:end]
            y_batch = y_shuffled[start:end]

            weights, batch_loss = opt.step_and_cost(
                lambda w: cost(w, X_batch, y_batch), weights
            )
            epoch_loss += float(batch_loss)

        avg_loss = epoch_loss / n_batches

        # Print progress every 5 epochs
        if (epoch + 1) % 5 == 0 or epoch == 0:
            # Quick train accuracy on subsample
            train_pred = predict_batch(X_train[:100], weights)
            train_acc = accuracy_score(y_train[:100], train_pred)
            print(f"    Epoch {epoch+1:>3}/{N_EPOCHS}  "
                  f"loss={avg_loss:.4f}  "
                  f"train_acc(100)={train_acc:.4f}")

    train_time = time.perf_counter() - t0
    print(f"\n  Training complete in {train_time:.1f}s")

    return weights, train_time


# ---------------------------------------------------------------------------
# Metrics (same schema as Phase 4)
# ---------------------------------------------------------------------------

def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    train_time: float,
) -> dict:
    """Compute metrics in the fixed Phase 4 schema + quantum-specific fields."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "model": "quantum_vqc",
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 6),
        "false_positive_rate": round(fpr, 6),
        "confusion_matrix": cm.tolist(),
        "training_time_seconds": round(train_time, 2),
        # Quantum-specific fields
        "n_qubits": N_QUBITS,
        "n_layers": N_LAYERS,
        "n_epochs": N_EPOCHS,
        "training_sample_size": TRAIN_SUBSAMPLE,
        "pca_components": N_QUBITS,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Train quantum VQC and evaluate on full test set."""
    print()
    print("+" + "=" * 62 + "+")
    print("|  SentinelAI -- Phase 5: Quantum VQC Training" + " " * 16 + "|")
    print("+" + "=" * 62 + "+")
    print()

    # Step 1: Load and PCA reduce
    print("[1/5] Loading data and applying PCA ...")
    X_train_pca, y_train, X_test_pca, y_test, pca = load_and_reduce()
    print()

    # Step 2: Subsample training data
    print(f"[2/5] Subsampling training set: {len(y_train)} -> {TRAIN_SUBSAMPLE} "
          f"(stratified, for simulator speed)")
    X_train_sub, y_train_sub = subsample_train(X_train_pca, y_train, TRAIN_SUBSAMPLE)
    n0 = int(np.sum(y_train_sub == 0))
    n1 = int(np.sum(y_train_sub == 1))
    print(f"  Subsample class balance: normal={n0}, anomaly={n1}")
    print(f"  NOTE: Evaluation will use FULL test set ({len(y_test)} samples)")
    print()

    # Step 3: Train
    print("[3/5] Training variational quantum classifier ...")
    print(f"  Circuit: {N_QUBITS} qubits, {N_LAYERS} layers "
          f"(StronglyEntanglingLayers), angle encoding")
    weights, train_time = train_quantum(X_train_sub, y_train_sub)
    print()

    # Step 4: Evaluate on FULL test set
    print("[4/5] Evaluating on FULL test set ...")
    print(f"  Predicting {len(y_test)} samples (this may take a moment) ...")
    pred_t0 = time.perf_counter()
    y_pred = predict_batch(X_test_pca, weights)
    pred_time = time.perf_counter() - pred_t0
    print(f"  Prediction complete in {pred_time:.1f}s")
    print()

    metrics = compute_metrics(y_test, y_pred, train_time)

    print("  Test set results:")
    cm = metrics["confusion_matrix"]
    print(f"    Accuracy           : {metrics['accuracy']:.4f}")
    print(f"    Precision          : {metrics['precision']:.4f}")
    print(f"    Recall             : {metrics['recall']:.4f}")
    print(f"    F1 Score           : {metrics['f1']:.4f}")
    print(f"    False Positive Rate: {metrics['false_positive_rate']:.4f}")
    print(f"    Training Time      : {metrics['training_time_seconds']:.2f}s")
    print(f"    Confusion Matrix   :")
    print(f"      TN={cm[0][0]:>6}  FP={cm[0][1]:>6}")
    print(f"      FN={cm[1][0]:>6}  TP={cm[1][1]:>6}")
    print()

    # Step 5: Save everything
    print("[5/5] Saving results ...")
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Save metrics
    metrics_path = _RESULTS_DIR / "quantum_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics  -> {metrics_path.name}")

    # Save PCA transform
    pca_path = _RESULTS_DIR / "pca_transform.joblib"
    joblib.dump(pca, pca_path)
    print(f"  PCA      -> {pca_path.name}")

    # Save trained weights
    weights_path = _RESULTS_DIR / "quantum_weights.npy"
    np.save(weights_path, np.array(weights))
    print(f"  Weights  -> {weights_path.name}")

    print()
    print("+" + "=" * 62 + "+")
    print("|  Quantum VQC training complete.                              |")
    print("|  Run compare_results.py for side-by-side comparison.        |")
    print("+" + "=" * 62 + "+")


if __name__ == "__main__":
    main()
