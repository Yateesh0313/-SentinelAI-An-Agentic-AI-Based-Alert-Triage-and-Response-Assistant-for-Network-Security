# 🛡️ Member Contribution: Backend & Cybersecurity Integrations

**Basaveshwar Engineering College (BEC), Bagalkote**  
**Department of Computer Science & Engineering | Final Year B.E. | VTU 2027**

- **Team Member**: Praveen Nashi
- **USN**: `2BA23CS071`
- **Core Domain**: Backend Architecture & Cybersecurity Integrations
- **Active Branch**: `Praveen-Nashi`

---

## 🎯 Executive Summary & Role Overview

As the **Backend & Cybersecurity Integrations Lead**, my primary responsibility was engineering the core server infrastructure, security engines, and external cybersecurity tool integrations of SentinelAI. 

My work connected the machine learning detectors and agentic reasoning pipelines with real-time SOC operations—providing a high-concurrency **FastAPI** service, persistent asynchronous **MongoDB** storage, strict **JWT-based RBAC**, a deterministic **5-signal risk scoring engine (0–100)**, and direct integrations with industry-standard cybersecurity tools including **Suricata 7.0 IDS (with 47,000+ Emerging Threats rules)**, **YARA signatures**, and **AbuseIPDB threat intelligence**.

---

## 🛠️ Architectural Responsibilities & Key Deliverables

### 1. High-Performance API & WebSocket Server (`backend/main.py`)
- Engineered a fully asynchronous **FastAPI** backend supporting bidirectional WebSocket streaming to deliver real-time alert events to analysts without polling.
- Developed REST endpoints for live replay control, Suricata engine management (`/suricata/start`, `/suricata/stop`, `/suricata/status`), honeypot listeners, and analyst review decisions (`/events/{id}/approve`, `/reject`, `/investigate`).
- Enforced strict state transitions preventing double-actions (HTTP 409 Conflict guards).

### 2. Centralized 5-Signal Risk Scoring Engine (`backend/risk_scoring.py`)
- Formulated and implemented a calibrated, auditable weighted risk-scoring formula (0–100):
  $$\text{Risk Score} = \sum_{i=1}^{5} w_i \cdot s_i$$
  - $w_1 = 0.30$: ML Anomaly Confidence / Suricata Alert Signal
  - $w_2 = 0.25$: Threat Intelligence Reputation (AbuseIPDB confidence score)
  - $w_3 = 0.20$: YARA Signature Pattern Matches
  - $w_4 = 0.15$: MITRE ATT&CK Technique Severity Weight
  - $w_5 = 0.10$: Traffic Ingestion Source Baseline (Honeypot, Suricata, Live, Replay)
- Output normalized classification tiers: `LOW` (0–39), `MEDIUM` (40–69), `HIGH` (70–84), `CRITICAL` (85–100).

### 3. Suricata 7.0 IDS & PCAP Replay Ingestion (`ml/live_capture/suricata_ingest.py`)
- Architected the live Intrusion Detection System integration utilizing **Suricata 7.0** with the **Emerging Threats Open ruleset (47,000+ signatures)**.
- Replaced passive Zeek logging with active pre-classified signature alerts (`eve.json`), routing high-confidence detections directly into the agentic triage pipeline without statistical ML bottlenecks.
- Built automated subprocess management and PCAP replay simulation for reproducible offline evaluation.

### 4. Database Persistence & RBAC Security (`backend/database.py`, `backend/auth.py`)
- Integrated **MongoDB 7** via the asynchronous **Motor** driver, designing atomic document updates for the entire alert lifecycle (`pending_review` $\to$ `approved` / `rejected` / `investigating`).
- Implemented **JWT (JSON Web Tokens)** with bcrypt password hashing, token expiration, and Role-Based Access Control (RBAC) ensuring only authorized SOC analysts can execute response actions.

### 5. Threat Intelligence & Signature Detection (`backend/enrichment.py`, `ml/signatures/`)
- Integrated external threat intelligence APIs (**AbuseIPDB** for IP reputation scoring and **ip-api.com** for GeoIP location context).
- Created native **YARA** signature rules for known attack payloads (Telnet root shells, FTP anomalies, ICMP tunneling).

---

## 📂 Core Files Authored & Maintained

| File | Purpose |
|---|---|
| `backend/main.py` | FastAPI application, REST endpoints, WebSocket broadcast hub, Suricata routing |
| `backend/risk_scoring.py` | 5-signal weighted risk scoring algorithm and classification logic |
| `backend/database.py` | MongoDB connection manager, Motor async queries, atomic event state updates |
| `backend/auth.py` | JWT generation, password hashing, and analyst RBAC middleware |
| `backend/enrichment.py` | AbuseIPDB threat intelligence client and GeoIP lookup service |
| `ml/live_capture/suricata_ingest.py` | Suricata 7.0 engine wrapper, eve.json parser, and PCAP replay harness |
| `ml/signatures/` | YARA signature rule definitions and matching engine |
| `ml/honeypot/` | Controlled TCP honeypot decoy listener for threat attribution |
| `tests/test_risk_scoring.py` | 6 unit tests validating risk weights, boundary conditions, and null resilience |
| `tests/test_suricata.py` | 6 unit tests validating Suricata event ingestion, severity mapping, and PCAP replay |
| `tests/test_approval_guard.py` | Tests verifying atomic state transitions and 409 Conflict double-action guards |

---

## 🧪 Validation & Test Coverage

- **Automated Tests**: 14 dedicated backend & security tests passing with 100% success rate:
  - `test_weights_sum_to_one`: Asserts mathematical validity of the risk formula ($w = 1.0$).
  - `test_risk_scoring_suricata_alert`: Validates calibrated risk elevation on signature matches.
  - `test_atomic_approve_and_double_guard`: Confirms atomic locks and prevents duplicate approvals.
  - `test_suricata_pcap_replay_end_to_end`: Asserts full ingest $\to$ parse $\to$ score cycle.
