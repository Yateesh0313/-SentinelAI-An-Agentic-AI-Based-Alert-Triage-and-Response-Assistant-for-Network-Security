"""NSL-KDD dataset loader and preprocessor.

Parses .arff files manually (scipy.io.arff chokes on malformed nominal
declarations in this dataset), encodes categoricals, scales numerics,
and saves processed splits for downstream model training.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent
_RAW_DIR = _THIS_DIR / "raw" / "nsl_kdd"
_PROCESSED_DIR = _THIS_DIR / "processed"

_TRAIN_FULL = _RAW_DIR / "KDDTrain+.arff"
_TRAIN_20 = _RAW_DIR / "KDDTrain+_20Percent.arff"
_TEST = _RAW_DIR / "KDDTest+.arff"

# The three categorical columns in the NSL-KDD dataset
CATEGORICAL_COLS: list[str] = ["protocol_type", "service", "flag"]


# ---------------------------------------------------------------------------
# 1. load_arff
# ---------------------------------------------------------------------------

def load_arff(filepath: str | Path) -> pd.DataFrame:
    """Parse a single .arff file into a pandas DataFrame.

    Reads @attribute lines to get column names, then reads CSV rows after
    the @data marker.  This avoids scipy.io.arff which fails on the
    malformed nominal declaration for ``protocol_type``.

    Returns
    -------
    pd.DataFrame
        DataFrame with 42 columns (41 features + 'class').
    """
    filepath = Path(filepath)
    col_names: list[str] = []
    data_start_idx: int = -1

    with open(filepath, encoding="utf-8") as fh:
        lines = fh.readlines()

    # Pass 1 — extract column names from @attribute lines
    for idx, line in enumerate(lines):
        stripped = line.strip()
        lower = stripped.lower()

        if lower.startswith("@attribute"):
            # Format: @attribute 'name' type_or_{values}
            # Strip @attribute, then parse the quoted or unquoted name
            rest = stripped[len("@attribute"):].strip()
            if rest.startswith("'"):
                end_quote = rest.index("'", 1)
                name = rest[1:end_quote]
            else:
                name = rest.split()[0]
            col_names.append(name)

        elif lower.startswith("@data"):
            data_start_idx = idx + 1
            break

    if data_start_idx < 0:
        raise ValueError(f"No @data marker found in {filepath}")
    if len(col_names) != 42:
        raise ValueError(
            f"Expected 42 columns but parsed {len(col_names)} from {filepath}"
        )

    # Pass 2 — read CSV data rows
    data_rows: list[list[str]] = []
    for line in lines[data_start_idx:]:
        stripped = line.strip()
        if stripped and not stripped.startswith("%"):
            data_rows.append(stripped.split(","))

    df = pd.DataFrame(data_rows, columns=col_names)

    # Convert numeric columns to float (everything except categoricals and class)
    for col in df.columns:
        if col not in CATEGORICAL_COLS and col != "class":
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


# ---------------------------------------------------------------------------
# 2. load_nsl_kdd
# ---------------------------------------------------------------------------

def load_nsl_kdd(
    use_20_percent: bool = False,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load NSL-KDD train and test sets as raw DataFrames.

    Parameters
    ----------
    use_20_percent : bool
        If True, load the smaller 20% training subset (faster iteration).

    Returns
    -------
    (train_df, test_df)
        Two DataFrames with original string values, no encoding applied.
    """
    train_path = _TRAIN_20 if use_20_percent else _TRAIN_FULL
    test_path = _TEST

    if not train_path.exists():
        raise FileNotFoundError(f"Training file not found: {train_path}")
    if not test_path.exists():
        raise FileNotFoundError(f"Test file not found: {test_path}")

    train_df = load_arff(train_path)
    test_df = load_arff(test_path)

    return train_df, test_df


# ---------------------------------------------------------------------------
# 3. preprocess
# ---------------------------------------------------------------------------

def preprocess(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    save: bool = True,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Encode, scale, and split into numpy arrays.

    - OneHotEncoder (fit on train only, handle_unknown='ignore') for
      protocol_type, service, flag.
    - StandardScaler (fit on train only) for all numeric features.
    - Class label: 'normal' -> 0, everything else (anomaly) -> 1.

    Parameters
    ----------
    train_df, test_df : pd.DataFrame
        Raw DataFrames from ``load_nsl_kdd``.
    save : bool
        If True, persist processed arrays and fitted transformers to
        ``ml/data/processed/``.

    Returns
    -------
    (X_train, y_train, X_test, y_test)
        All as numpy arrays.  X arrays are float64, y arrays are int64.
    """
    # --- Labels -----------------------------------------------------------
    y_train = (train_df["class"] != "normal").astype(np.int64).values
    y_test = (test_df["class"] != "normal").astype(np.int64).values

    # --- Feature matrices (drop class column) -----------------------------
    train_feats = train_df.drop(columns=["class"])
    test_feats = test_df.drop(columns=["class"])

    # --- Numeric columns --------------------------------------------------
    numeric_cols = [c for c in train_feats.columns if c not in CATEGORICAL_COLS]

    scaler = StandardScaler()
    train_numeric = scaler.fit_transform(
        train_feats[numeric_cols].values.astype(np.float64)
    )
    test_numeric = scaler.transform(
        test_feats[numeric_cols].values.astype(np.float64)
    )

    # --- Categorical columns (OneHot, fit on train only) ------------------
    encoder = OneHotEncoder(
        sparse_output=False,
        handle_unknown="ignore",   # test has categories unseen in train
        dtype=np.float64,
    )
    train_cat = encoder.fit_transform(train_feats[CATEGORICAL_COLS])
    test_cat = encoder.transform(test_feats[CATEGORICAL_COLS])

    # --- Combine numeric + one-hot ----------------------------------------
    X_train = np.hstack([train_numeric, train_cat])
    X_test = np.hstack([test_numeric, test_cat])

    # --- Hard check: column counts must match -----------------------------
    if X_train.shape[1] != X_test.shape[1]:
        raise ValueError(
            f"Column count mismatch after encoding! "
            f"X_train has {X_train.shape[1]} cols, "
            f"X_test has {X_test.shape[1]} cols."
        )

    # --- Save artifacts ---------------------------------------------------
    if save:
        _PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

        np.save(_PROCESSED_DIR / "train_X.npy", X_train)
        np.save(_PROCESSED_DIR / "train_y.npy", y_train)
        np.save(_PROCESSED_DIR / "test_X.npy", X_test)
        np.save(_PROCESSED_DIR / "test_y.npy", y_test)

        joblib.dump(scaler, _PROCESSED_DIR / "scaler.joblib")
        joblib.dump(encoder, _PROCESSED_DIR / "encoder.joblib")

        print(f"  Saved processed arrays to {_PROCESSED_DIR}")
        print(f"  Saved scaler  -> scaler.joblib")
        print(f"  Saved encoder -> encoder.joblib")

    return X_train, y_train, X_test, y_test
