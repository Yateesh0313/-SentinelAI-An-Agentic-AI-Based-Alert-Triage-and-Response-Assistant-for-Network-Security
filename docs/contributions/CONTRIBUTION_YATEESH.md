# 🤖 Member Contribution: Agentic AI & LLM Orchestration

**Basaveshwar Engineering College (BEC), Bagalkote**  
**Department of Computer Science & Engineering | Final Year B.E. | VTU 2027**

- **Team Member**: Yateesh Mattur
- **USN**: `2BA23CS125`
- **Core Domain**: Agentic AI & LLM Orchestration
- **Active Branch**: `Yateesh0313-patch-1`

---

## 🎯 Executive Summary & Role Overview

As the **Agentic AI & LLM Orchestration Lead**, my primary responsibility was architecting and implementing the intelligent reasoning core of SentinelAI. While traditional SOC tools produce disjointed alerts and static rule matches, SentinelAI leverages an autonomous multi-agent pipeline orchestrated via **LangGraph** and powered by ultra-low-latency LLM inference via the **Groq API** (Qwen 2.5 / Llama 3).

The agentic pipeline transforms raw anomaly detections into structured, actionable security intelligence—explaining *why* an event occurred in plain English, assessing business impact, classifying threat severity, mapping MITRE ATT&CK techniques, and formulating recommended response playbooks for human SOC analysts.

---

## 🛠️ Architectural Responsibilities & Key Deliverables

### 1. Multi-Agent Pipeline Orchestration (`agents/pipeline.py`)
- Designed and built the stateful **LangGraph** computation graph managing the sequential triage workflow:
  $$\text{Input Anomaly} \longrightarrow [\text{Triage Agent}] \longrightarrow [\text{Severity Agent}] \longrightarrow [\text{Response Agent}] \longrightarrow \text{Action Proposal}$$
- Implemented state passing using Pydantic schemas, ensuring guaranteed JSON schemas for backend and frontend consumption.
- Configured resilient fallback handlers and error boundaries so if an LLM rate-limit or API timeout occurs, the system defaults to deterministic heuristic fallback scores without dropping alerts.

### 2. LLM Inference via Groq API
- Orchestrated low-latency inference using Groq's LPUs (Language Processing Units) running Qwen 2.5 and Llama 3 models, achieving sub-second reasoning loops per flagged event.
- Designed system prompts and few-shot security context injection preventing hallucinations and enforcing standardized SOC terminology (RFC 2828 / NIST SP 800-61).

### 3. MITRE ATT&CK Technique Mapping (`agents/attack_mapping.py`)
- Created rule-based heuristics that automatically map detected network traffic patterns and signature flags to standardized MITRE ATT&CK Enterprise Tactics & Techniques:
  - **T1498**: Network Denial of Service (SYN flood, Neptune, Smurf)
  - **T1046**: Network Service Discovery (Port scanning, Satan, Nmap probes)
  - **T1110**: Brute Force Authentication (FTP/SSH/Telnet login bursts)
  - **T1041**: Exfiltration Over C2 Channel (Abnormal outbound byte volume)
  - **T1068**: Exploitation for Privilege Escalation (Buffer overflow, rootkit attempts)

### 4. Human-in-the-Loop Response Recommendation
- Authored the response formulation agent that recommends contextual mitigation actions:
  - `block_ip`: Firewall rule injection recommendation for high-confidence brute force/DoS attacks.
  - `isolate_host`: Containment recommendation for privilege escalation/lateral movement.
  - `rate_limit`: Throttling recommendation for high-volume service scanning.
  - `flag_for_review`: Observational recommendation for ambiguous medium-severity anomalies.
- Ensured recommendations are strictly advisory until approved by an authenticated analyst via the dashboard.

---

## 📂 Core Files Authored & Maintained

| File | Purpose |
|---|---|
| `agents/pipeline.py` | LangGraph multi-agent orchestration, state definitions, and agent nodes |
| `agents/attack_mapping.py` | MITRE ATT&CK technique mapping engine and pattern matchers |
| `agents/prompts.py` | SOC analyst system prompts, response formatting guidelines, and guardrails |
| `agents/requirements.txt` | LangChain, LangGraph, Groq, and Pydantic dependency configurations |
| `tests/test_matchers.py` | Automated test suite validating MITRE ATT&CK mapping accuracy |
| `scripts/seed_demo.py` | Multi-agent execution pipeline harness for demo alert generation |

---

## 🧪 Validation & Test Coverage

- **Automated Tests**: 9 dedicated unit and heuristic tests in `tests/test_matchers.py` validating:
  - True-positive ATT&CK mappings across DoS, Port Scan, Brute Force, and Data Exfiltration.
  - True-negative validation ensuring clean baseline traffic never produces spurious ATT&CK tags.
- **Latency Benchmark**: Average agent pipeline execution time $\le 0.85\text{s}$ per alert under Groq inference.
