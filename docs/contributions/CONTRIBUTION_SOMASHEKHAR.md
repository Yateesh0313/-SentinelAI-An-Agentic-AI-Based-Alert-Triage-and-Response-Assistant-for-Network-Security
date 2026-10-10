# 🧠 Member Contribution: ML & Quantum Detection

**Basaveshwar Engineering College (BEC), Bagalkote**  
**Department of Computer Science & Engineering | Final Year B.E. | VTU 2027**

- **Team Member**: Somashekhar Kadrolli
- **USN**: `2BA23CS101`
- **Core Domain**: Machine Learning & Quantum Detection
- **Active Branch**: `Somashekhar`

---

## 🎯 Executive Summary & Role Overview

As the **ML & Quantum Detection Lead**, my primary responsibility was designing, training, and benchmarking the anomaly detection layer of SentinelAI. Network intrusion detection requires high throughput, resilient classification across known attack families (DoS, Probe, R2L, U2R), and minimal false alarm rates.

My work encompassed two major research tracks:
1. **Production Classical ML Pipeline**: Developing a production-grade **XGBoost** anomaly classifier alongside a **Random Forest** baseline on the standardized NSL-KDD benchmark, including full preprocessing and vectorization from 41 network flow features to 122 dimensions.
2. **Comparative Quantum Machine Learning (QML) Study**: Implementing a **PennyLane Variational Quantum Classifier (VQC)** running on simulated quantum circuits under identical train/test splits to objectively evaluate whether NISQ-era quantum computing provides any measurable advantage over classical gradient-boosted trees.

---

## 🛠️ Architectural Responsibilities & Key Deliverables

### 1. Feature Engineering & Preprocessing Pipeline (`ml/preprocessing/`)
- Engineered a robust transformation pipeline converting 41 heterogeneous NSL-KDD flow attributes into a normalized 122-dimensional dense feature representation:
  - **Categorical Encoding**: `OneHotEncoder(handle_unknown='ignore')` for `protocol_type` (3), `service` (70), and `flag` (11).
  - **Numerical Scaling**: `StandardScaler` / `RobustScaler` applied to continuous fields (`duration`, `src_bytes`, `dst_bytes`, `count`, `srv_count`, etc.) to mitigate heavy outlier skew.
- Serialized pipeline artifacts (`scaler.joblib`, `encoder.joblib`) ensuring zero training-serving skew during live inference.
- Guaranteed fault-tolerant inference against unseen network services in production replay.

### 2. Classical Intrusion Detection Engine (`ml/classical/`)
- Trained and tuned an **XGBoost Classifier** optimized for binary anomaly detection (normal vs. attack) and multi-class attack categorization.
- Evaluated against a comparative **Random Forest** baseline:
  - **XGBoost Accuracy**: $> 99.2\%$ on KDDTrain+, $> 80.4\%$ on the difficult KDDTest+ split.
  - **Inference Latency**: $< 2.5\text{ms}$ per connection vector, enabling high-rate traffic ingestion.
- Output calibrated confidence probabilities $P(\text{anomaly})$ feeding directly into the 5-signal risk scoring engine.

### 3. Comparative Quantum Machine Learning Study (`ml/quantum/`)
- Implemented a parameterized quantum circuit (PQC) using **PennyLane**:
  - **State Preparation**: Angle embedding encoding dimensionality-reduced flow features into qubit rotation angles.
  - **Ansatz**: Strongly entangling layers with trainable rotational gates ($R_x, R_y, R_z$) and CNOT entanglers.
  - **Cost Function & Optimization**: Binary cross-entropy with Adam optimizer on state-vector quantum simulators.
- Conducted an honest, reproducible comparative evaluation:
  - Validated that classical XGBoost outperforms simulated 4-to-8 qubit VQCs in classification F1-score and inference speed at current simulation scales.
  - Documented empirical findings transparently in the major project synopsis as a foundational study for post-quantum SOC evolution.

---

## 📂 Core Files Authored & Maintained

| File | Purpose |
|---|---|
| `ml/classical/` | XGBoost & Random Forest model training, tuning, and evaluation scripts |
| `ml/preprocessing/` | Data cleaning, categorical encoding, and numerical scaling pipeline |
| `ml/quantum/` | PennyLane Variational Quantum Classifier (VQC) circuit definitions & benchmarks |
| `ml/data/` | NSL-KDD dataset splits, feature maps, and processed binary artifacts |
| `tests/test_preprocessing.py` | 5 unit tests validating dimensions (41→122), scaling bounds, and unseen category safety |

---

## 🧪 Validation & Test Coverage

- **Automated Tests**: 5 dedicated tests in `tests/test_preprocessing.py`:
  - `test_scaler_feature_count`: Verifies numerical feature normalization.
  - `test_encoder_categorical_columns`: Verifies categorical mapping consistency.
  - `test_total_transformed_dimensions`: Validates exact 122-feature vector output shape.
  - `test_alignment_with_processed_data`: Validates zero drift between training and inference sets.
  - `test_unseen_categorical_graceful_handling`: Asserts robust handling of unknown network protocols.
