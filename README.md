# SIH1684 — Advanced Agent-less Windows Vulnerability and Network Scanner

An AI-assisted cybersecurity platform for identifying, analyzing, prioritizing, and remediating security vulnerabilities across authorized Windows systems and networks — without requiring a dedicated agent on every endpoint.

---

## Prerequisites

- Docker 24+ and Docker Compose v2
- Python 3.12 (for local dev)
- Node 20+ and npm 10+ (for local dev)
- Nmap (installed separately for real scans; mocked in tests)

---

## Quick Start (Docker)

```bash
# 1. Copy and configure environment variables
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD and SECRET_KEY at minimum

# 2. Start all services
docker-compose up -d

# 3. Run DB migrations
docker-compose exec backend alembic upgrade head

# 4. Seed demo data
docker-compose exec backend python -m app.demo.seed_demo

# 5. Open the UI
# Frontend: http://localhost:3000
# API docs: http://localhost:8000/docs
```

---

## Local Development (without Docker for app code)

```bash
# Start only db + redis in Docker
docker-compose -f docker-compose.dev.yml up -d

# Backend
cd backend
pip install -r requirements.txt -r requirements-dev.txt
cp ../.env.example ../.env   # edit DATABASE_URL / REDIS_URL if needed
alembic upgrade head
python -m app.demo.seed_demo
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

---

## Demo Credentials

| Role    | Username | Password      |
|---------|----------|---------------|
| Admin   | admin    | Admin@1234    |
| Analyst | analyst  | Analyst@1234  |
| Viewer  | viewer   | Viewer@1234   |

---

## Running Tests

```bash
cd backend
pytest --cov=app tests/ -q
```

---

## Architecture

- **Backend**: FastAPI + SQLAlchemy 2.0 (async) + PostgreSQL
- **Workers**: Celery + Redis
- **Frontend**: React + TypeScript + Vite + Tailwind CSS + shadcn/ui
- **Scanning**: Nmap (network), WinRM/PowerShell (Windows assessment)
- **Vulnerability Intelligence**: NVD API 2.0, CISA KEV catalog

See `.agents/tasks/plan.md` for full architecture documentation.
