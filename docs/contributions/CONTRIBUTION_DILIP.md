# 🖥️ Member Contribution: Frontend, UI/UX & Deployment

**Basaveshwar Engineering College (BEC), Bagalkote**  
**Department of Computer Science & Engineering | Final Year B.E. | VTU 2027**

- **Team Member**: Dilip Holkar
- **USN**: `2BA24CS402`
- **Core Domain**: Frontend Architecture, UI/UX Design & Deployment
- **Active Branch**: `Dilip`

---

## 🎯 Executive Summary & Role Overview

As the **Frontend, UI/UX & Deployment Lead**, my primary responsibility was designing, building, and deploying the analyst-facing user experience and production infrastructure of SentinelAI. 

An advanced AI-driven SOC platform requires a user interface that avoids cognitive overload, enables instantaneous threat assessment, and provides seamless human-in-the-loop decision gating. I built a modern, responsive SOC dashboard using **Next.js 16**, **React 19**, **Tailwind CSS**, **shadcn/ui**, and **Framer Motion**, integrated with a cinematic 3D network visualization powered by **Three.js** and **GSAP**. On the operations side, I established containerized deployment via **Docker** and automated **GitHub Actions CI/CD workflows**.

---

## 🛠️ Architectural Responsibilities & Key Deliverables

### 1. Next.js 16 & React 19 SOC Dashboard (`frontend/src/app/dashboard/page.tsx`)
- Developed a high-density, real-time Security Operations Center (SOC) dashboard displaying:
  - **Live Threat Stream**: Streaming alerts arriving via WebSockets without page reload.
  - **Animated Collapsible Triage Cards**: Built with `@radix-ui/react-collapsible` and Framer Motion, enabling analysts to smoothly expand and collapse deep agentic reasoning trails, raw packet payloads, and MITRE ATT&CK badges.
  - **Human-in-the-Loop Approval Hub**: One-click actions for `Approve Mitigation`, `Reject Alert`, and `Investigate Further` with double-action guards and optimistic UI updates.
  - **Live Engine Controls**: Interactive dashboard controls to launch/stop the **Suricata 7.0 IDS** engine, toggle the Honeypot listener, and control NSL-KDD dataset replay.

### 2. Modern UI Component Architecture (`frontend/src/components/ui/`)
- Implemented production-grade **shadcn/ui** design system components:
  - `button.tsx`: Variant-driven button primitive (default, destructive, outline, ghost, secondary).
  - `collapsible.tsx`: Accessible disclosure component for detailed alert forensics.
  - Badge and Card primitives tailored for dark-mode cybersecurity palettes with high-contrast severity color coding (`CRITICAL` in crimson, `HIGH` in amber, `MEDIUM` in cyan, `LOW` in slate).

### 3. Real-Time WebSocket Hook (`frontend/src/hooks/use-sentinel-ws.ts`)
- Engineered a custom React hook managing bidirectional WebSocket connections to the FastAPI backend:
  - Built-in exponential backoff and automatic reconnection upon network disruption.
  - Memory-bounded FIFO event queue preventing DOM bloat during high-throughput traffic replay.
  - Audio and visual cues for critical threat ingress.

### 4. 3D Cinematic Landing Page Hero (Three.js + GSAP)
- Designed an immersive 3D interactive hero visualization using **Three.js** and **GSAP**:
  - Dynamically renders an active network graph with pulsating threat nodes and packet trajectories.
  - Smooth scroll-triggered camera movements and typography entrance animations.

### 5. Deployment Infrastructure & CI/CD (`docker-compose.yml`, `.github/workflows/ci.yml`)
- Configured multi-container orchestration via **Docker Compose** provisioning MongoDB 7 and application dependencies.
- Authored the automated GitHub Actions CI pipeline (`ci.yml`) executing Python pytest suites and Next.js production builds on every push to ensure zero regression.

---

## 📂 Core Files Authored & Maintained

| File | Purpose |
|---|---|
| `frontend/src/app/dashboard/page.tsx` | Main SOC dashboard page, live event stream, and action triggers |
| `frontend/src/app/page.tsx` | Cinematic 3D landing page with GSAP animations & Three.js canvas |
| `frontend/src/components/ui/button.tsx` | Reusable shadcn/ui Button primitive |
| `frontend/src/components/ui/collapsible.tsx` | Radix UI accessible Collapsible disclosure primitive |
| `frontend/src/hooks/use-sentinel-ws.ts` | Resilient auto-reconnecting WebSocket client hook |
| `frontend/package.json` | Next.js 16, React 19, Radix UI, Lucide icons, and Tailwind dependencies |
| `docker-compose.yml` | Multi-service local and staging deployment specification |
| `.github/workflows/ci.yml` | Automated GitHub Actions CI workflow for backend and frontend tests |
| `tests/test_frontend_smoke.py` | Smoke test validating production Next.js build output across routes |

---

## 🧪 Validation & Test Coverage

- **Frontend Production Build**: Clean compilation under Turbopack in Next.js 16 with zero TypeScript errors across `/`, `/dashboard`, and `/login`.
- **Automated Smoke Tests**: 4 tests in `tests/test_frontend_smoke.py` verifying static artifact presence and route health.
- **Cross-Browser Verification**: Responsive layout verified across standard desktop, tablet, and mobile viewport dimensions.
