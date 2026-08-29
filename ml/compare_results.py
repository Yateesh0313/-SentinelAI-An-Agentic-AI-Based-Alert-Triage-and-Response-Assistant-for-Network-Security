"""SentinelAI -- Quantum vs Classical Comparison Table.

Loads all three results JSONs and prints a side-by-side comparison table.

Usage:
    python compare_results.py
"""

from __future__ import annotations

import json
from pathlib import Path

_RESULTS_DIR = Path(__file__).resolve().parent / "results"

# The three result files in display order
_FILES = [
    ("XGBoost", "classical_baseline_metrics.json"),
    ("Random Forest", "classical_rf_metrics.json"),
    ("Quantum VQC", "quantum_metrics.json"),
]

# Metrics to compare (must exist in all JSONs)
_METRICS = [
    ("accuracy", "Accuracy"),
    ("precision", "Precision"),
    ("recall", "Recall"),
    ("f1", "F1 Score"),
    ("false_positive_rate", "FPR"),
    ("training_time_seconds", "Train Time (s)"),
]


def main() -> None:
    """Load results and print comparison."""
    results: list[tuple[str, dict]] = []

    for label, filename in _FILES:
        path = _RESULTS_DIR / filename
        if not path.exists():
            print(f"  [SKIP] {filename} not found -- run the training script first.")
            continue
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        results.append((label, data))

    if len(results) < 2:
        print("Need at least 2 result files for comparison.")
        return

    # Header
    print()
    print("=" * 72)
    print("  SentinelAI -- Quantum vs Classical Comparison")
    print("=" * 72)
    print()

    # Column widths
    metric_w = 18
    col_w = 16

    # Table header
    header = f"  {'Metric':<{metric_w}}"
    for label, _ in results:
        header += f" {label:>{col_w}}"
    print(header)
    print(f"  {'-' * metric_w}" + f" {'-' * col_w}" * len(results))

    # Table rows
    for key, display_name in _METRICS:
        row = f"  {display_name:<{metric_w}}"
        for _, data in results:
            val = data.get(key, "N/A")
            if isinstance(val, float):
                if key == "training_time_seconds":
                    row += f" {val:>{col_w}.2f}"
                else:
                    row += f" {val:>{col_w}.4f}"
            else:
                row += f" {str(val):>{col_w}}"
        print(row)

    print()

    # Confusion matrices
    print("  Confusion Matrices (rows: actual, cols: predicted):")
    print(f"  {'':>{metric_w}}", end="")
    for label, _ in results:
        print(f"  {label:>{col_w * 2}}", end="")
    print()

    cm_labels = ["TN/FP", "FN/TP"]
    for i, row_label in enumerate(cm_labels):
        line = f"  {row_label:<{metric_w}}"
        for _, data in results:
            cm = data.get("confusion_matrix", [[0, 0], [0, 0]])
            line += f"  {cm[i][0]:>7} / {cm[i][1]:<7}"
        print(line)

    print()

    # Quantum-specific notes
    for label, data in results:
        if "n_qubits" in data:
            print(f"  Quantum model notes:")
            print(f"    Qubits           : {data.get('n_qubits', 'N/A')}")
            print(f"    Circuit layers   : {data.get('n_layers', 'N/A')}")
            print(f"    Training epochs  : {data.get('n_epochs', 'N/A')}")
            print(f"    Training samples : {data.get('training_sample_size', 'N/A')} "
                  f"(subsampled from full train set)")
            print(f"    PCA components   : {data.get('pca_components', 'N/A')}")
            print()

    # Fair comparison caveat
    print("  " + "-" * 68)
    print("  NOTE: The quantum model was trained on a subsample due to")
    print("  simulator constraints. Classical models used the full training")
    print("  set. All models were evaluated on the identical full test set")
    print("  (KDDTest+). This asymmetry is standard in quantum-classical")
    print("  comparison studies and should be noted in any report.")
    print("  " + "-" * 68)
    print()
    print("=" * 72)


if __name__ == "__main__":
    main()
