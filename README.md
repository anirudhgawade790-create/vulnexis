# SIH1684 — Agent-less Windows Vulnerability & Network Scanner

SIH1684 is a web platform for authorized network discovery, Windows security
assessment, vulnerability and finding management, and remediation tracking.
It combines a React dashboard with a FastAPI API and background scan workers.

> **Use responsibly:** Scan only systems and networks that you own or have
> explicit permission to assess. A scan can generate network traffic and may
> affect monitored or sensitive systems.

## What it does

- Discover network hosts and open ports with Nmap.
- Assess supported Windows systems remotely through WinRM/PowerShell.
- Correlate scan observations with vulnerabilities, including NVD and CISA KEV
  information.
- Review assets, findings, scan history, risk, remediation, and baseline
  assessment results.
- Manage users and roles, and inspect administrative audit information.
- Process scans in the background with Celery and Redis, with scan progress
  exposed through the API and WebSocket.

## Technology

| Area | Stack |
|---|---|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| API | FastAPI, Pydantic, SQLAlchemy async |
| Database | PostgreSQL (Docker setup); SQLite is the application default |
| Background jobs | Celery and Redis |
| Scanning | Nmap, WinRM/PowerShell |
| Vulnerability data | NVD API and CISA KEV catalog |

## Requirements

### Docker setup

- Docker Desktop (or Docker Engine) with Docker Compose v2.

### Local application development

- Python 3.12
- Node.js 20+ and npm
- Docker Compose v2 for the PostgreSQL and Redis services
- Nmap for real network scans; make sure it is installed and available at the
  configured `NMAP_PATH`.
- WinRM access and valid credentials for Windows assessment targets.

## Choose one run mode

There are two supported ways to run the application. Do not start the full
Docker stack and a local backend at the same time: both try to bind port 8000.

| Mode | Frontend | Backend | Database and Redis |
|---|---|---|---|
| Full Docker | `http://localhost:3000` | `http://localhost:8000` | Docker |
| Local development | `http://localhost:5173` | `http://localhost:8000` | Docker |

## Full Docker setup

Run these commands from the repository root. In PowerShell, copy the example
environment file with `Copy-Item`:

```powershell
Copy-Item .env.example .env
```

Edit `.env` before starting the services:

1. Set a strong `POSTGRES_PASSWORD`.
2. Set `SECRET_KEY` to a new, private random value (at least 32 characters).
3. Set `DATABASE_URL` to use the Docker service hostname `db`, not `localhost`:

   ```text
   postgresql+asyncpg://sih1684:<POSTGRES_PASSWORD>@db:5432/sih1684
   ```

   Replace `<POSTGRES_PASSWORD>` with the same value configured for
   `POSTGRES_PASSWORD`.
4. Keep `REDIS_URL`, `CELERY_BROKER_URL`, and `CELERY_RESULT_BACKEND` pointed
   at `redis://redis:6379/...` when the backend and worker run in Docker.
5. `NVD_API_KEY` is optional and can be set for NVD requests.

Start the stack and apply database migrations:

```powershell
docker compose up -d --build
docker compose exec backend alembic upgrade head
```

To load sample users, assets, scans, and findings, run the idempotent demo
seeder:

```powershell
docker compose exec backend python -m app.demo.seed_demo
```

Alternatively, set `DEMO_MODE=true` before starting the backend to create
tables and seed demo data at application startup. For a normal migrated
database, leave it `false`.

Open:

- Frontend: <http://localhost:3000>
- API documentation: <http://localhost:8000/docs>
- Health check: <http://localhost:8000/health>

Useful Docker commands:

```powershell
docker compose ps
docker compose logs -f backend
docker compose logs -f worker
docker compose down
```

`docker compose down` stops and removes the containers but keeps the named
database volume. Avoid `docker compose down -v` unless you deliberately want to
delete the database data.

## Local development setup

This mode runs only PostgreSQL and Redis in Docker. The API, Celery worker, and
Vite frontend run locally. First copy `.env.example` to `.env` in the
repository root as described above. The Compose file reads that root file.
Because the backend loads `.env` from its current working directory, also
create a backend-local copy:

```powershell
cd backend
Copy-Item ..\.env .env
```

Edit `backend\.env` for the host-side connection values:

- `DATABASE_URL` should use `localhost:5432` (not `db`), for example:
  `postgresql+asyncpg://sih1684:<POSTGRES_PASSWORD>@localhost:5432/sih1684`.
- Redis URLs should use `localhost:6379`.
- Ensure the password in `DATABASE_URL` matches `POSTGRES_PASSWORD`.

Start the supporting services from the repository root:

```powershell
docker compose -f docker-compose.dev.yml up -d
```

In a new terminal, set up and start the backend:

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt -r requirements-dev.txt
alembic upgrade head
python -m app.demo.seed_demo
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Run the Celery worker in another terminal. Activate the same virtual
environment and run:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
celery -A app.workers.celery_app worker --loglevel=info --pool=solo
```

Run the frontend in a third terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open <http://localhost:5173>. Vite proxies `/api` and `/ws` requests to
`http://localhost:8000`.

### macOS/Linux command equivalents

Use `cp .env.example .env`, activate the virtual environment with
`source .venv/bin/activate`, and use `docker compose` as shown above. The
backend and frontend commands are otherwise the same.

## Configuration

Settings are loaded from `.env` (see `.env.example`). Important settings:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy database connection. Use host `db` inside Docker and `localhost` for local app processes. |
| `POSTGRES_PASSWORD` | Password for the PostgreSQL container; keep it consistent with `DATABASE_URL`. |
| `REDIS_URL` | Redis connection for application access. |
| `CELERY_BROKER_URL` | Redis database used as the Celery broker. |
| `CELERY_RESULT_BACKEND` | Redis database used for Celery results. |
| `SECRET_KEY` | JWT signing secret. Replace the example value; never use it in production. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access-token lifetime. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh-token lifetime. |
| `CORS_ORIGINS` | Comma-separated allowed browser origins. |
| `DEMO_MODE` | When `true`, create tables and seed demo data at backend startup. |
| `NVD_API_KEY` | Optional NVD API key. |
| `OPENAI_API_KEY` | Optional key for integrations that use OpenAI. |
| `NMAP_PATH` | Path to the Nmap executable. The Docker image installs it at `/usr/bin/nmap`. |
| `DEFAULT_SCAN_TIMEOUT` | Default scan timeout in seconds. |
| `MAX_CONCURRENT_SCANS` | Maximum concurrent scans setting. |

For local development, the default database URL in application settings uses
SQLite if `DATABASE_URL` is not set. The Docker Compose setup provides
PostgreSQL. For the settings used by the app, the timeout variable is
`DEFAULT_SCAN_TIMEOUT`.

## Demo accounts

The demo seeder creates these sample accounts:

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@1234` |
| Analyst | `analyst` | `Analyst@1234` |
| Viewer | `viewer` | `Viewer@1234` |

These are public demo credentials. Do not use them outside a local demo
environment; change or remove them before exposing an instance.

## Tests and frontend checks

Run backend tests from the `backend` directory:

```powershell
pytest --cov=app tests/ -q
```

Run frontend checks from the `frontend` directory:

```powershell
npm run lint
npm run build
```

## API overview

The API is versioned under `/api/v1`. Interactive request and response
documentation is available at `/docs` while the backend is running. Main
resource groups include:

- `/auth`, `/users`, `/admin`
- `/targets`, `/scans`, `/assets`
- `/vulnerabilities`, `/findings`, `/remediation`
- `/baseline`, `/dashboard`
- `/ws/scan/{scan_job_id}` for scan progress

## Troubleshooting

### Port 8000 is already in use (`WinError 10048`)

Another process is already listening on the backend port. This commonly
happens when a local Uvicorn process is still running while the Docker backend
is started, or when two backend servers are started.

Find the process in PowerShell:

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen |
  Select-Object LocalAddress, LocalPort, OwningProcess
Get-Process -Id <PID>
```

Stop it only after confirming it is the old backend process:

```powershell
Stop-Process -Id <PID>
```

Choose either full Docker or local-backend mode above. To run the local API on
another port, start Uvicorn with `--port 8001` and update the Vite proxy target
in `frontend/vite.config.ts` to `http://localhost:8001`.

### Backend cannot connect to PostgreSQL

Check that the `db` service is healthy with `docker compose ps` and verify the
host in `DATABASE_URL`: use `db` from containers, `localhost` from a local
process. Confirm the database password matches `POSTGRES_PASSWORD`, then
apply migrations with `alembic upgrade head` (or the Docker command above).

### Scans remain queued or do not start

Confirm Redis is running and that the Celery broker/result URLs use the correct
hostname for the selected run mode. Also confirm the Celery worker is running
and check its logs.

### Browser cannot reach the API

In local development, keep the backend on port 8000 because Vite's `/api` and
`/ws` proxies target that port by default. In full Docker mode, check that the
backend container is healthy and port 8000 is not occupied by another process.

## Repository layout

```text
backend/
  app/
    routers/       API endpoints
    schemas/       Request and response models
    models/        Database models
    services/      Business logic
    scanners/      Network and Windows scan pipeline
    workers/       Celery app and scan tasks
    demo/          Demo data seeder
  alembic/         Database migrations
  tests/           Backend tests
frontend/
  src/
    api/           API client functions
    components/    Shared UI components
    pages/         Application pages
docker-compose.yml       Full stack
docker-compose.dev.yml   Local-development dependencies
```
#   v u l n e x i s  
 