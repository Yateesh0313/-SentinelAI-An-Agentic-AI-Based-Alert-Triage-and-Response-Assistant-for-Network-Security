"""Verification script for the NSL-KDD data loader.

Runs load_nsl_kdd() and preprocess(), then prints diagnostics:
  - Shapes of X_train, y_train, X_test, y_test
  - Column count match check (hard stop if mismatched)
  - Class balance in y_train and y_test
  - NaN check across all four arrays
  - First row of X_train as a sanity check

Usage:
    python verify_loader.py              # uses 20% train subset (default)
    python verify_loader.py --full       # uses full KDDTrain+.arff
"""

from __future__ import annotations

import sys

import numpy as np

from loader import load_nsl_kdd, preprocess


def main() -> None:
    """Run verification checks."""
    use_full = "--full" in sys.argv
    subset_label = "KDDTrain+.arff (FULL)" if use_full else "KDDTrain+_20Percent.arff"

    print("=" * 64)
    print("  SentinelAI -- NSL-KDD Data Loader Verification")
    print("=" * 64)
    print(f"  Training file: {subset_label}")
    print()

    # ------------------------------------------------------------------
    # Step 1: Load raw DataFrames
    # ------------------------------------------------------------------
    print("[1/5] Loading raw .arff files ...")
    train_df, test_df = load_nsl_kdd(use_20_percent=not use_full)

    print(f"  Raw train shape: {train_df.shape}")
    print(f"  Raw test  shape: {test_df.shape}")
    print(f"  Columns ({len(train_df.columns)}): {list(train_df.columns[:5])} ... {list(train_df.columns[-3:])}")
    print()

    # ------------------------------------------------------------------
    # Step 2: Preprocess (encode + scale + save)
    # ------------------------------------------------------------------
    print("[2/5] Preprocessing (encode categoricals, scale numerics) ...")
    X_train, y_train, X_test, y_test = preprocess(train_df, test_df, save=True)
    print()

    # ------------------------------------------------------------------
    # Step 3: Shape checks
    # ------------------------------------------------------------------
    print("[3/5] Shape checks:")
    print(f"  X_train : {X_train.shape}  dtype={X_train.dtype}")
    print(f"  y_train : {y_train.shape}  dtype={y_train.dtype}")
    print(f"  X_test  : {X_test.shape}  dtype={X_test.dtype}")
    print(f"  y_test  : {y_test.shape}  dtype={y_test.dtype}")

    if X_train.shape[1] != X_test.shape[1]:
        print()
        print("  *** HARD STOP: Column count MISMATCH! ***")
        print(f"  X_train has {X_train.shape[1]} columns")
        print(f"  X_test  has {X_test.shape[1]} columns")
        sys.exit(1)
    else:
        print(f"  Column count match: OK ({X_train.shape[1]} columns each)")
    print()

    # ------------------------------------------------------------------
    # Step 4: Class balance
    # ------------------------------------------------------------------
    print("[4/5] Class balance:")
    train_normal = int(np.sum(y_train == 0))
    train_anomaly = int(np.sum(y_train == 1))
    test_normal = int(np.sum(y_test == 0))
    test_anomaly = int(np.sum(y_test == 1))

    print(f"  y_train: normal={train_normal}, anomaly={train_anomaly}  "
          f"({train_anomaly / len(y_train) * 100:.1f}% anomaly)")
    print(f"  y_test : normal={test_normal}, anomaly={test_anomaly}  "
          f"({test_anomaly / len(y_test) * 100:.1f}% anomaly)")
    print()

    # ------------------------------------------------------------------
    # Step 5: NaN check + first-row sanity
    # ------------------------------------------------------------------
    print("[5/5] Data quality:")
    arrays = {"X_train": X_train, "y_train": y_train,
              "X_test": X_test, "y_test": y_test}
    all_clean = True
    for name, arr in arrays.items():
        nan_count = int(np.isnan(arr).sum())
        status = "OK (no NaNs)" if nan_count == 0 else f"*** {nan_count} NaN values! ***"
        print(f"  {name}: {status}")
        if nan_count > 0:
            all_clean = False

    print()
    print("  First row of X_train (sanity check):")
    print(f"  {X_train[0, :10]}  ... ({X_train.shape[1]} total features)")
    print()

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("=" * 64)
    if all_clean and X_train.shape[1] == X_test.shape[1]:
        print("  ALL CHECKS PASSED -- data is ready for model training.")
    else:
        print("  SOME CHECKS FAILED -- review output above.")
    print("=" * 64)


if __name__ == "__main__":
    main()
