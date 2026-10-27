<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0c29,50:302b63,100:24243e&height=200&section=header&text=VulnExis&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=Advanced%20Agentless%20Vulnerability%20%26%20Network%20Scanner&descAlignY=60&descSize=18&animation=fadeIn" width="100%"/>

<br/>

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-00b894?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178c6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Python](https://img.shields.io/badge/Python-3.12-ffd43b?style=for-the-badge&logo=python&logoColor=black)](https://python.org)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-3.4-38bdf8?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![SQLite](https://img.shields.io/badge/SQLite-ready-003b57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)

<br/>

> ### 🔥 *Discover. Assess. Remediate. No agents. No BS.*
> Enterprise-grade security scanning platform — built for **SIH 2024 · Problem Statement 1684**

<br/>

```
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗  ██╗██╗███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝╚██╗██╔╝██║██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗   ╚███╔╝ ██║███████╗
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝   ██╔██╗ ██║╚════██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗██╔╝ ██╗██║███████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝
```

</div>

---

<div align="center">

## 💀 What makes VulnExis different?

| | Other Tools | VulnExis |
|--|-------------|----------|
| 🤖 Agent Required | ✅ Yes | ❌ No |
| 💸 Cost | 💰 Expensive | 🆓 Free & Open |
| 🪟 Windows Deep Scan | ❌ Limited | ✅ Full WinRM/PS |
| � CISA KEV Integration | ❌ Rarely | ✅ Built-in |
| � Explainable Risk | ❌ Black box | ✅ Full breakdown |
| ⚡ Real-time Progress | ❌ Polling | ✅ SSE + WebSocket |

</div>

---

## ⚡ 60-Second Setup

```powershell
# 1. Clone
git clone https://github.com/your-org/vulnexis.git && cd vulnexis

# 2. Backend — Terminal 1
cd backend
pip install -r requirements.txt
uvicorn app.main:app --port 8000

# 3. Frontend — Terminal 2
cd frontend
npm install && npm run dev
```

### 🌐 Open → `http://localhost:5173`

| 👑 Admin | 🔍 Analyst | 👁️ Viewer |
|----------|-----------|----------|
| `admin` / `Admin@1234` | `analyst` / `Analyst@1234` | `viewer` / `Viewer@1234` |

> No PostgreSQL needed. SQLite runs out of the box. DEMO_MODE auto-seeds everything.

---

## 🎯 Features that hit different

<table>
<tr>
<td width="50%">

### 🌐 Network Intelligence
- Nmap-powered host discovery
- Port scanning with service fingerprinting
- Risky service detection (RDP, Telnet, SMB)
- Network Risk Map visualization

</td>
<td width="50%">

### 🪟 Windows Deep Dive
- Agentless via WinRM/PowerShell
- Missing patches detection
- Defender, Firewall, SMB, RDP checks
- Software inventory
- Password policy assessment

</td>
</tr>
<tr>
<td width="50%">

### 🔴 Vulnerability Intel
- NVD API v2.0 integration
- CISA Known Exploited Vulnerabilities (KEV)
- CVSS v3 scoring & vectors
- CWE classification

</td>
<td width="50%">

### 🧠 Smart Risk Engine
- Explainable risk scores (0–10)
- Factors: CVSS + KEV + exposure + criticality
- AI Insights (rule-based, no hallucinations)
- Change detection between scans

</td>
</tr>
<tr>
<td width="50%">

### �️ Remediation
- Step-by-step PowerShell scripts
- Admin warning on every command block
- Effort estimation badges
- One-click verify & close

</td>
<td width="50%">

### � Compliance
- CIS Windows Server benchmark
- NIST CSF framework
- Stacked compliance charts
- Per-control pass/fail/unknown

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                   🌐 BROWSER                     │
│        React 18  •  TypeScript  •  Vite          │
│    Tailwind CSS  •  shadcn/ui  •  Recharts       │
└───────────────────────┬─────────────────────────┘
                        │  REST / SSE / WebSocket
┌───────────────────────▼─────────────────────────┐
│               ⚡ FASTAPI BACKEND                 │
│     JWT Auth  •  Rate Limiting  •  Audit Log     │
│         SQLAlchemy Async  •  Pydantic v2         │
└────────┬──────────────────────────┬──────────────┘
         │                          │
┌────────▼────────┐      ┌──────────▼──────────┐
│   🗄️ DATABASE   │      │   ⚙️ CELERY WORKER   │
│ SQLite / Postgres│      │   Background Scans   │
└─────────────────┘      └──────────┬───────────┘
                                    │
          ┌─────────────────────────┼────────────────────┐
          │                         │                    │
   ┌──────▼──────┐         ┌────────▼────────┐  ┌───────▼──────┐
   │  🌐 NETWORK  │         │  🪟 WINDOWS      │  │  🔍 CVE       │
   │   SCANNER   │         │   SCANNER       │  │  CORRELATOR  │
   │    (Nmap)   │         │  (WinRM + PS)   │  │  NVD + KEV   │
   └─────────────┘         └─────────────────┘  └──────────────┘
```

---

## 📁 Project Structure

```
vulnexis/
│
├── � backend/
│   ├── app/
│   │   ├── � routers/        ← 11 API route files
│   │   ├── �️  models/         ← 8 SQLAlchemy models
│   │   ├── � schemas/        ← Pydantic schemas
│   │   ├── ⚙️  services/       ← Risk engine, insights, remediation
│   │   ├── � scanners/       ← Nmap, WinRM, CVE correlator, orchestrator
│   │   ├── � workers/        ← Celery tasks
│   │   └── 🌱 demo/           ← Deterministic demo seeder
│   ├── alembic/               ← DB migrations
│   ├── tests/                 ← 10 pytest test files
│   └── Dockerfile
│
├── ⚛️  frontend/
│   ├── src/
│   │   ├── � api/            ← Axios API client (11 modules)
│   │   ├── 🧩 components/     ← 40+ UI components
│   │   ├── � pages/          ← 13 page components
│   │   ├── 🪝 hooks/          ← React Query hooks
│   │   ├── 🏪 store/          ← Zustand auth store
│   │   └── � types/          ← TypeScript interfaces
│   └── vite.config.ts
│
├── 🐳 docker-compose.yml       ← Full stack
├── 🐳 docker-compose.dev.yml   ← Dev (DB + Redis only)
└── ⚙️  .env.example
```

---

## 🐳 Docker Setup

```powershell
# Copy & configure env
Copy-Item .env.example .env
# Edit .env: set POSTGRES_PASSWORD, SECRET_KEY
# Update DATABASE_URL host to 'db' (not localhost)

# Launch everything
docker compose up -d --build

# Migrate + seed
docker compose exec backend alembic upgrade head
docker compose exec backend python -m app.demo.seed_demo
```

🌍 Open **http://localhost:3000** · API Docs **http://localhost:8000/docs**

---

## 🔌 API Reference

> 📖 Full interactive docs at **`http://localhost:8000/docs`**

```
/api/v1/
├── 🔐 auth/         login · refresh · logout · me
├── 👤 users/        CRUD · role management
├── 🎯 targets/      scope management
├── 🔍 scans/        launch · cancel · SSE progress · results · compare
├── 💻 assets/       inventory · findings · history
├── 🐛 vulnerabilities/  CVE list · KEV · sync from NVD
├── 🚨 findings/     list · status update · assign · remediation
├── 🛠️  remediation/  prioritized plan · verify
├── 📋 baseline/     policies · assess · results
├── 📊 dashboard/    summary · trends · insights · top-risks
└── 📡 /ws/scan/{id}  WebSocket live progress
```

---

## ⚙️ Environment Variables

```bash
# .env — copy from .env.example

DATABASE_URL=sqlite+aiosqlite:///./sih1684.db   # SQLite default
SECRET_KEY=your-secret-min-32-chars              # 🔴 Change this!
DEMO_MODE=true                                   # Auto-seed on startup
CORS_ORIGINS=["http://localhost:5173"]           # JSON array format
NVD_API_KEY=                                     # Optional, higher rate limits
NMAP_PATH=/usr/bin/nmap                          # Path to nmap binary
```

---

## 🧪 Tests

```powershell
# Backend — 10 test files, ~60% coverage
cd backend
pytest --cov=app tests/ -q

# Frontend — type check + build
cd frontend
npm run build
```

---

## 🐛 Common Issues

<details>
<summary>🔴 <b>Port 8000 already in use</b></summary>

```powershell
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```
</details>

<details>
<summary>🔴 <b>Login failed</b></summary>

```powershell
# Check backend health
curl http://localhost:8000/health
# → {"status":"ok"}
```
Backend + frontend dono chal rahe hain na? Dono alag terminals mein chahiye.
</details>

<details>
<summary>🔴 <b>CORS error in browser</b></summary>

`.env` mein check karo:
```bash
CORS_ORIGINS=["http://localhost:5173"]   # JSON array, quotes required
```
</details>

<details>
<summary>🔴 <b>Scans stuck in queued</b></summary>

```powershell
# Redis + Celery worker chahiye
docker compose -f docker-compose.dev.yml up -d redis
cd backend
celery -A app.workers.celery_app worker --loglevel=info --pool=solo
```
</details>

---

<div align="center">

## 🏆 Built for Smart India Hackathon 2024

**Problem Statement · SIH1684**

*Agentless Windows Vulnerability and Network Scanner*

---

### 📊 Project Stats

![Lines of Code](https://img.shields.io/badge/Lines%20of%20Code-15000%2B-blueviolet?style=for-the-badge)
![API Endpoints](https://img.shields.io/badge/API%20Endpoints-35%2B-orange?style=for-the-badge)
![UI Components](https://img.shields.io/badge/UI%20Components-40%2B-pink?style=for-the-badge)
![Test Files](https://img.shields.io/badge/Test%20Files-10-green?style=for-the-badge)

---

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:24243e,50:302b63,100:0f0c29&height=120&section=footer" width="100%"/>

*Made with 💜 | Scan responsibly*

</div>
