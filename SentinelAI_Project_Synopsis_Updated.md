# SentinelAI
## An Agentic AI-Based Alert Triage and Response Assistant for Network Security
### with a Comparative Quantum-Classical Detection Study

**Basaveshwar Engineering College (BEC), Bagalkote**  
**Department of Computer Science & Engineering | Final Year B.E. | VTU 2027**  
**Project Synopsis**

---

### Domain
**Artificial Intelligence & Cybersecurity**

---

### Problem Statement
Security teams are flooded with thousands of alerts a day, the large majority of which are false positives. This causes alert fatigue, where genuine threats get buried in noise and are missed. There is a need for a system that can triage alerts intelligently, explain its reasoning transparently, and still leave final decision-making authority with a human analyst rather than fully automating response actions.

---

### Project Description
Security Operations Centers (SOCs) are overwhelmed by alert volume — most flagged events are false positives, causing genuine threats to be missed in the noise. SentinelAI addresses this with an agentic AI pipeline that ingests network traffic, detects anomalies, explains findings in plain English, assigns severity, recommends a response, and requires explicit human approval before any action is marked executed.

Detection combines classical machine learning (XGBoost, Random Forest) with a comparative quantum machine learning study using PennyLane on the same NSL-KDD dataset, evaluating whether quantum models offer any measurable advantage at current simulation scale — reported honestly regardless of outcome. A YARA-based signature layer runs alongside ML detection, demonstrating the classic SOC hybrid of known-pattern matching plus anomaly detection. Live local network traffic capture and PCAP replay powered by Suricata 7.0 (using the Emerging Threats Open ruleset of 47,000+ signatures) and a controlled honeypot module extend detection beyond static dataset replay to genuinely live, locally-sourced events. Unlike passive forensic logging, Suricata outputs pre-classified alerts (`eve.json`) that route directly into agentic triage alongside honeypot detections.

Detected anomalies pass through a LangGraph-orchestrated multi-agent reasoning pipeline — Triage, Severity, and Response agents built on the Groq API — each explaining and scoring the event, with every recommendation logged and gated behind human approval. Findings are further enriched with MITRE ATT&CK technique mapping, threat intelligence and GeoIP lookups via public reputation APIs, and a centralized weighted risk-scoring engine (0–100) combining ML confidence, threat intel reputation, signature matches, and ATT&CK severity — presented alongside the LLM's own severity judgment for direct comparison between formula-based and reasoning-based assessment. Alerts follow a full lifecycle (pending, investigating, resolved, false positive), all persisted in MongoDB.

The platform is presented through a JWT-authenticated Next.js dashboard featuring a cinematic, GSAP-animated homepage with a 3D network visualization hero, live event feed, reasoning trail, threat map, and MITRE technique breakdown — built with production-grade shadcn/ui primitives and Framer Motion layout animations for a polished, responsive interface.

SentinelAI adapts and extends active applied-security research — LLM agents for SOC alert triage — into a deployable prototype, contributing an original quantum-classical comparative study and the integration of multiple detection paradigms (ML, signature-based, honeypot-sourced) into a single auditable, human-gated pipeline.

---

### Objectives
- **Design a multi-agent LLM pipeline** (Triage → Severity → Response) that explains and scores network anomalies in plain English, with every action gated by explicit human approval.
- **Build and evaluate classical ML models** (XGBoost, Random Forest) for network intrusion detection on the NSL-KDD dataset.
- **Conduct a comparative study** of a PennyLane-based variational quantum classifier against the classical baseline under identical evaluation conditions.
- **Integrate a YARA-based signature detection layer** alongside ML detection to demonstrate a hybrid SOC-style detection architecture.
- **Extend detection beyond static dataset replay** using live local traffic capture and PCAP replay (Suricata 7.0 with Emerging Threats Open rules) and a controlled honeypot module.
- **Enrich detections** with MITRE ATT&CK technique mapping and threat intelligence / GeoIP lookups from public reputation APIs.
- **Build a centralized, auditable risk-scoring engine** combining multiple detection signals into a normalized 0–100 score, alongside LLM-assigned severity with agreement metrics.
- **Deliver a secure (JWT-authenticated with RBAC), interactive Next.js dashboard** built on shadcn/ui and Framer Motion for real-time monitoring, alert review, and atomic human-in-the-loop approval.

---

### System Architecture

| Stage | Description |
|---|---|
| **Data Ingestion** | Network traffic (NSL-KDD replay, live Suricata 7.0 IDS capture & PCAP replay, honeypot connections) is ingested as structured flow and alert events. |
| **Detection Layer** | Classical ML (XGBoost / Random Forest) and a parallel PennyLane quantum classifier flag anomalies; YARA rules and Suricata Emerging Threats signatures run alongside for known-pattern matching. |
| **Agentic Reasoning Layer** | LangGraph pipeline (Triage → Severity → Response agents, powered by the Groq API) explains, scores, and recommends an action for each flagged event. |
| **Enrichment** | MITRE ATT&CK technique mapping, threat intelligence (AbuseIPDB) and GeoIP lookups add context to each detection. |
| **Risk Scoring** | A 5-signal weighted formula combines ML confidence, threat intel score, signature matches, and ATT&CK severity into a normalized 0–100 risk score and classification. |
| **Human-in-the-Loop** | A JWT-authenticated dashboard requires explicit analyst approval or rejection with double-action guards before any recommended action is marked executed. |
| **Storage** | MongoDB persists all events, detections, agent decisions, enrichment data, and approval history. |
| **Visualization** | A Next.js dashboard built with shadcn/ui and Framer Motion presents a live event feed, reasoning trail, threat map, and MITRE technique breakdown. |

---

### Technology Stack

| Layer | Technology |
|---|---|
| **Dataset** | NSL-KDD (public, labelled network intrusion dataset) |
| **Classical ML** | Python, scikit-learn, XGBoost, Random Forest |
| **Quantum ML** | PennyLane (variational quantum classifier) |
| **Agent Orchestration** | LangChain + LangGraph |
| **LLM** | Groq API (Qwen 2.5 / Llama 3 on free tier) |
| **Signature Detection** | YARA (offline/replay) + Suricata 7.0 ET Open (live/pcap) |
| **Live Traffic Capture & IDS** | Suricata 7.0 (Emerging Threats Open ruleset of 47,000+ signatures) |
| **Threat Intelligence** | AbuseIPDB (reputation) + GeoIP (ip-api.com) |
| **Backend** | FastAPI, Uvicorn, WebSockets, JWT authentication + RBAC |
| **Database** | MongoDB 7 (Motor async driver) |
| **Frontend** | Next.js 16, React 19, Tailwind CSS, GSAP, React Three Fiber |
| **UI Component Libraries** | shadcn/ui, Framer Motion |
| **Real-time Updates** | WebSockets |
| **Deployment** | Docker + Render / AWS free tier / Local SOC |

---

### Methodology / Development Approach
The system has been developed and validated through 24 verifiable, incremental phases — project scaffolding, agent pipeline setup, dataset preprocessing, classical baseline training, quantum model training and comparison, backend integration, human-in-the-loop approval, persistence, cybersecurity tool integration (MITRE ATT&CK, threat intelligence, YARA, Suricata IDS live capture & replay, honeypot), authentication, an interactive cinematic dashboard (shadcn/ui + Framer Motion), and a centralized risk-scoring engine — with each phase independently run and verified against a 33-test automated regression suite before completion.

---

### Expected Outcome
- **A working, deployable prototype** demonstrating end-to-end agentic alert triage with human oversight.
- **An honest, reproducible comparison** of classical versus quantum machine learning for network anomaly detection.
- **A hybrid multi-tier detection architecture** combining ML classification, Suricata/YARA signature-based matching, and honeypot deception sources into a unified pipeline.
- **A polished, interactive dashboard** built with shadcn/ui and Framer Motion, suitable for real-time live demonstration.

---

### Team Details

| # | Name | USN |
|---|---|---|
| 1 | **Yateesh Mattur** | 2BA23CS125 |
| 2 | **Somashekhar Kadrolli** | 2BA23CS101 |
| 3 | **Praveen Nashi** | 2BA23CS071 |
| 4 | **Dilip Holkar** | 2BA24CS402 |

---

### References

#### Datasets and Frameworks
- M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, “A Detailed Analysis of the KDD CUP 99 Data Set,” in *Proc. IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA)*, 2009. (Origin of the NSL-KDD dataset.)
- NSL-KDD Dataset — Canadian Institute for Cybersecurity, University of New Brunswick. https://www.unb.ca/cic/datasets/nsl.html
- MITRE ATT&CK Framework — https://attack.mitre.org
- Suricata Intrusion Detection System — Open Information Security Foundation (OISF). https://suricata.io
- Emerging Threats Open Ruleset — Proofpoint. https://rules.emergingthreats.net

#### Machine Learning and Quantum Computing
- T. Chen and C. Guestrin, “XGBoost: A Scalable Tree Boosting System,” in *Proc. 22nd ACM SIGKDD Int. Conf. on Knowledge Discovery and Data Mining*, 2016.
- L. Breiman, “Random Forests,” *Machine Learning*, vol. 45, no. 1, pp. 5–32, 2001.
- M. Schuld and F. Petruccione, *Machine Learning with Quantum Computers*, 2nd ed., Springer, 2021.
- V. Bergholm et al., “PennyLane: Automatic Differentiation of Hybrid Quantum-Classical Computations,” *arXiv:1811.04968*, Xanadu Quantum Technologies. https://pennylane.ai

#### Agentic AI and LLM Orchestration
- LangGraph Documentation — LangChain AI. https://langchain-ai.github.io/langgraph/
- Groq API Documentation — https://groq.com
- T. Guo et al., “Large Language Model Based Multi-Agents: A Survey of Progress and Challenges,” *arXiv:2402.01680*, 2024.

#### Cybersecurity Tools and Services
- YARA Documentation — https://yara.readthedocs.io
- AbuseIPDB — IP reputation and abuse reporting service. https://www.abuseipdb.com
- ip-api.com — IP Geolocation API. https://ip-api.com

#### Related Research
- N. Moustafa and J. Slay, “The Evaluation of Network Anomaly Detection Systems: Statistical Analysis of the UNSW-NB15 Data Set,” *Information Security Journal*, 2016.
- B. A. Tama and S. Lim, “Ensemble Learning for Intrusion Detection Systems: A Systematic Mapping Study and Cross-Benchmark Evaluation,” *Computer Science Review*, vol. 39, 2021.
- M. Kaur and A. Kaur, “AI-Driven Security Operations Center Automation: A Review of Alert Triage Approaches,” in *Proc. Int. Conf. on Computing and Communication Technologies*, 2023.
