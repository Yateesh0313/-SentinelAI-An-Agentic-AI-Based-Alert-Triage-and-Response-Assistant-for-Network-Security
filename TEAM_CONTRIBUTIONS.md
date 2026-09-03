# 👥 SentinelAI — Comprehensive Team Work & Contributions

**Basaveshwar Engineering College (BEC), Bagalkote**  
**Department of Computer Science & Engineering | Final Year B.E. | VTU 2027**  
**Domain: Artificial Intelligence & Cybersecurity**

---

## 🏛️ Project Leadership & Architectural Contribution Matrix

SentinelAI is developed collaboratively by a 4-member final year engineering team at Basaveshwar Engineering College (Autonomous), affiliated with Visvesvaraya Technological University (VTU), Belagavi. Each member leads a distinct architectural pillar of the platform:

| # | Team Member | USN | Core Domain & Focus | Dedicated Role Document | Active Git Branch |
|---|---|---|---|---|---|
| 1 | **Yateesh Mattur** | `2BA23CS125` | **Agentic AI & LLM Orchestration** | [`docs/contributions/CONTRIBUTION_YATEESH.md`](docs/contributions/CONTRIBUTION_YATEESH.md) | [`Yateesh0313-patch-1`](https://github.com/Yateesh0313/-SentinelAI-An-Agentic-AI-Based-Alert-Triage-and-Response-Assistant-for-Network-Security/tree/Yateesh0313-patch-1) |
| 2 | **Somashekhar Kadrolli** | `2BA23CS101` | **ML & Quantum Detection** | [`docs/contributions/CONTRIBUTION_SOMASHEKHAR.md`](docs/contributions/CONTRIBUTION_SOMASHEKHAR.md) | [`Somashekhar`](https://github.com/Yateesh0313/-SentinelAI-An-Agentic-AI-Based-Alert-Triage-and-Response-Assistant-for-Network-Security/tree/Somashekhar) |
| 3 | **Praveen Nashi** | `2BA23CS071` | **Backend & Cybersecurity Integrations** | [`docs/contributions/CONTRIBUTION_PRAVEEN.md`](docs/contributions/CONTRIBUTION_PRAVEEN.md) | [`Praveen-Nashi`](https://github.com/Yateesh0313/-SentinelAI-An-Agentic-AI-Based-Alert-Triage-and-Response-Assistant-for-Network-Security/tree/Praveen-Nashi) |
| 4 | **Dilip Holkar** | `2BA24CS402` | **Frontend, UI/UX & Deployment** | [`docs/contributions/CONTRIBUTION_DILIP.md`](docs/contributions/CONTRIBUTION_DILIP.md) | [`Dilip`](https://github.com/Yateesh0313/-SentinelAI-An-Agentic-AI-Based-Alert-Triage-and-Response-Assistant-for-Network-Security/tree/Dilip) |

---

## 🔍 Detailed Contributions by Team Member

### 1. Yateesh Mattur (`2BA23CS125`) — Agentic AI & LLM Orchestration
- **LangGraph Multi-Agent Architecture**: Designed and built the sequential state graph (`agents/pipeline.py`) routing anomalous events through dedicated **Triage**, **Severity**, and **Response Recommendation** agent nodes.
- **Groq LPU Inference**: Integrated ultra-low-latency LLM inference (Qwen 2.5 and Llama 3 models) via the Groq API, generating natural language explanations and security justifications in $< 0.85$ seconds.
- **MITRE ATT&CK Heuristics**: Authored technique mapping rules (`agents/attack_mapping.py`) correlating traffic features to tactics T1498 (DoS), T1046 (Scanning), T1110 (Brute Force), T1041 (Exfiltration), and T1068 (Privilege Escalation).
- **Advisory Response Formulations**: Developed contextual response formulation proposing actions (`block_ip`, `isolate_host`, `rate_limit`, `flag_for_review`) while enforcing human authorization.
- **Detailed Specification**: See [Yateesh's Full Role Document](docs/contributions/CONTRIBUTION_YATEESH.md).

---

### 2. Somashekhar Kadrolli (`2BA23CS101`) — ML & Quantum Detection
- **Classical Anomaly Detection**: Built and benchmarked **XGBoost** and **Random Forest** models on the standard NSL-KDD benchmark, achieving $> 99.2\%$ training accuracy and $> 80.4\%$ test accuracy on the difficult KDDTest+ split.
- **Preprocessing Pipeline (41 → 122 Dimensions)**: Engineered normalization and one-hot encoding pipelines (`ml/preprocessing/`) converting raw 41 flow attributes to normalized 122-feature vectors with robust handling for unknown categories.
- **PennyLane Quantum VQC Study**: Implemented a Variational Quantum Classifier running parameterized quantum circuits (PQCs) with angle embedding and entangling layers to empirically compare quantum NISQ performance against classical baselines.
- **Evaluation & Preprocessor Artifacts**: Saved serialized model artifacts (`scaler.joblib`, `encoder.joblib`) ensuring zero training-serving skew during live inference.
- **Detailed Specification**: See [Somashekhar's Full Role Document](docs/contributions/CONTRIBUTION_SOMASHEKHAR.md).

---

### 3. Praveen Nashi (`2BA23CS071`) — Backend & Cybersecurity Integrations
- **FastAPI REST & WebSocket Server**: Engineered the high-concurrency asynchronous API server (`backend/main.py`) and live alert broadcast hub.
- **MongoDB Persistence & Atomic Guards**: Integrated MongoDB 7 using the async **Motor** driver, enforcing atomic state transitions (`pending_review` $\to$ `approved` / `rejected` / `investigating`) with 409 Conflict double-action guards.
- **JWT & Role-Based Access Control**: Implemented secure authentication and authorization (`backend/auth.py`) with bcrypt password hashing.
- **5-Signal Risk Scoring Engine (0–100)**: Formulated the multi-tier weighted risk formula combining ML confidence, AbuseIPDB reputation, YARA signature matches, ATT&CK severity, and source baselines into normalized classifications (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Suricata 7.0 IDS Integration**: Integrated live local loopback capture, PCAP replay, and structured `eve.json` parsing (47,000+ Emerging Threats rules).
- **YARA & Honeypot**: Built signature matching engine (`ml/signatures/`) and TCP deception listener (`ml/honeypot/`).
- **Detailed Specification**: See [Praveen's Full Role Document](docs/contributions/CONTRIBUTION_PRAVEEN.md).

---

### 4. Dilip Holkar (`2BA24CS402`) — Frontend, UI/UX & Deployment
- **Next.js 16 & React 19 SOC Dashboard**: Developed the responsive analyst dashboard (`frontend/src/app/dashboard/page.tsx`) with real-time alert feed, metrics overview, and action controls.
- **Modern Component Design System**: Implemented accessible **shadcn/ui** primitives ([`button.tsx`](frontend/src/components/ui/button.tsx), [`collapsible.tsx`](frontend/src/components/ui/collapsible.tsx)) and custom dark-mode cybersecurity palettes.
- **Motion & Disclosure Forensics**: Built smooth **Framer Motion** collapsible cards allowing analysts to inspect LLM reasoning trails, raw packet payloads, and MITRE badges without interface clutter.
- **3D Cinematic Hero (Three.js + GSAP)**: Designed dynamic 3D network node visualizer with interactive camera physics on the landing page (`frontend/src/app/page.tsx`).
- **Resilient WebSocket Client**: Created auto-reconnecting WebSocket hook (`frontend/src/hooks/use-sentinel-ws.ts`) with bounded FIFO memory queue.
- **DevOps & CI/CD**: Authored multi-container `docker-compose.yml` and automated GitHub Actions test workflow (`.github/workflows/ci.yml`).
- **Detailed Specification**: See [Dilip's Full Role Document](docs/contributions/CONTRIBUTION_DILIP.md).

---

## 🧪 Verification & Automated Regression Suite

The unified platform has been verified against a 33-test automated regression suite:

| Test Module | Coverage Area | Tests | Status |
|---|---|---|---|
| `test_approval_guard.py` | Atomic state transitions & 409 Conflict guards | 2 | ✅ PASSED |
| `test_matchers.py` | MITRE ATT&CK heuristics & YARA signature rules | 9 | ✅ PASSED |
| `test_preprocessing.py` | 41→122 dim scaler/encoder feature transformations | 5 | ✅ PASSED |
| `test_risk_scoring.py` | 5-signal weighted risk formula & boundaries | 6 | ✅ PASSED |
| `test_suricata.py` | Suricata subprocess, eve.json parser & PCAP replay | 6 | ✅ PASSED |
| `test_integration.py` | End-to-end ingest $\to$ triage $\to$ score $\to$ approve | 1 | ✅ PASSED |
| `test_frontend_smoke.py` | Production build & Next.js route verification | 4 | ✅ PASSED |
| **Total** | **All 7 Test Modules** | **33** | **✅ 100% Passing** |
