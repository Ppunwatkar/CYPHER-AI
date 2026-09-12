# CIPHER AI — Backend Foundation (v1 Phase 1)

Production-grade, asynchronous AI-first SecOps backend built with **Python 3.12+**, **FastAPI**, **SQLAlchemy 2.x**, and **PostgreSQL**.

---

## Overview & Architecture

The CIPHER AI backend powers the cybersecurity intelligence platform alongside the React/TypeScript frontend without modifying or redesigning the existing UI.

### Core Stack:
* **Runtime**: Python 3.12+
* **Web Framework**: FastAPI (ASGI)
* **ORM & Persistence**: SQLAlchemy 2.x (asyncpg driver) with pgvector architecture readiness
* **Database Migrations**: Alembic
* **Primary Database**: PostgreSQL
* **Testing**: pytest, pytest-asyncio, httpx

---

## Directory Structure

```text
backend/
├── app/
│   ├── main.py                 # FastAPI application, lifespan, middlewares, exception handlers
│   ├── config.py               # Pydantic Settings, safe CORS, dynamic database URLs
│   │
│   ├── api/
│   │   ├── __init__.py         # Router aggregations (/api/v1)
│   │   └── health.py           # GET /api/v1/health & GET /api/v1/system/health
│   │
│   ├── database/
│   │   ├── __init__.py         # Database exports
│   │   ├── base.py             # SQLAlchemy 2.x DeclarativeBase & naming conventions
│   │   ├── session.py          # Async engine, connection pooling, and connection probe
│   │   └── models/             # Persistent entity models (Phase 2+)
│   │
│   ├── models/                 # Domain models
│   ├── schemas/                # Pydantic request/response schemas
│   ├── services/               # Business logic services
│   ├── security/               # TLP authorization & RBAC
│   ├── agents/                 # Gemini autonomous agent orchestrators
│   ├── tools/                  # Tool Gateway & Policy Execution Sandbox
│   ├── intelligence/           # OSINT connectors (AbuseIPDB, Shodan, VT, NVD)
│   └── audit/                  # Append-only immutable audit trail
│
├── migrations/                 # Alembic migrations directory
├── tests/                      # pytest test suite
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variables template
├── Dockerfile                  # Production container definition
└── README.md                   # This documentation
```

---

## Setup & Running Locally

### 1. Initialize Virtual Environment & Install Dependencies
```bash
cd backend
python -m venv .venv
# On Windows PowerShell:
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and set your PostgreSQL connection string:
```bash
cp .env.example .env
```
Default connection string:
```env
DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5432/cipher_db"
```

### 3. Run Test Suite
```bash
pytest
```

### 4. Start Development Server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive API documentation will be available at:
* Swagger UI: `http://localhost:8000/docs`
* ReDoc: `http://localhost:8000/redoc`

---

## API Endpoints (Phase 1)

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Application status and live PostgreSQL ping latency probe. |
| `GET` | `/api/v1/system/health` | Comprehensive telemetry array matching frontend `SystemStatusModal` format. |
| `GET` | `/` | Root service metadata pointer. |

---

## Security Safeguards (Phase 1)

1. **Zero Secret Leakage**: No credentials logged; secrets isolated server-side.
2. **Safe CORS**: Rejects `*` wildcard origins when running in `production` or `staging`.
3. **Correlation Tracking**: Injects `X-Request-ID` and `X-Response-Time` into every request.
4. **Resilient Degradation**: If PostgreSQL is temporarily unreachable, API services report degraded state rather than crashing.
