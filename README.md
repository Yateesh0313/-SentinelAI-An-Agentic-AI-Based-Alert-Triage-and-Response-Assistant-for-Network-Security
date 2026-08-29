# SentinelAI

**Agentic AI Alert Triage & Response Assistant for Network Security**
with a Comparative Quantum-Classical Detection Study.

---

## Folder Structure

```
SentinelAI/
├── backend/          # FastAPI REST API
│   ├── main.py
│   └── requirements.txt
├── ml/               # Machine-learning experiments
│   ├── classical/    # Classical models (RF, XGBoost, …)
│   │   └── train_baseline.py
│   ├── quantum/      # Quantum models (PennyLane VQC, …)
│   │   └── train_quantum.py
│   ├── data/         # Datasets (KDD / NSL-KDD)
│   └── requirements.txt
├── agents/           # LangGraph agentic pipeline
│   ├── pipeline.py
│   └── requirements.txt
├── frontend/         # Next.js + TypeScript + Tailwind + shadcn/ui
│   └── (Next.js project files)
├── .gitignore
└── README.md         ← you are here
```

---

## How to Run Each Part

> Each part runs in its **own terminal**. They are independent until explicitly wired together in a later phase.

### 1. Backend (FastAPI)

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Open **http://127.0.0.1:8000/health** in a browser.
You should see: `{"status":"ok"}`

### 2. ML — Classical Baseline Stub

```bash
cd ml
pip install -r requirements.txt   # (optional for the stub)
python classical/train_baseline.py
```

You should see: `classical baseline stub ready`

### 3. ML — Quantum Model Stub

```bash
cd ml
python quantum/train_quantum.py
```

You should see: `quantum model stub ready`

### 4. Agents (LangGraph Pipeline)

```bash
cd agents
pip install -r requirements.txt
python pipeline.py
```

You should see three node names printed in order, followed by:
`Pipeline finished. Final state: { … }`

### 5. Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000** in a browser.
You should see a dashboard page with the heading **"SentinelAI Dashboard"** and
a status badge reading **"Backend: not connected yet"**.

---

## Prerequisites

| Tool    | Version       |
|---------|---------------|
| Python  | 3.10+         |
| Node.js | 18+ (LTS)     |
| npm     | 9+            |

---

## License

TBD
