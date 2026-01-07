# AI SOC Agent

Autonomous Security Operations Center agent that ingests alerts, investigates, makes contextual decisions, and performs tiered automated responses with full auditability.

## Contents
- Overview
- Quick Start
- Configuration
- Running (Dev & Docker)
- API Reference
- Admin Dashboard
- Security
- Architecture
- Development
- Version History
- Contributing
- License

## Overview
- Ingests and classifies alerts (EDR, Phishing, Cloud, Network, Identity).
- Investigates across data sources; correlates indicators; applies context.
- Makes decisions considering business impact and learned outcomes.
- Generates conclusions and executes automatic containment/response actions.
- Maintains incidents, forensic logs, and tamper-evident audit trail.
- Provides admin authentication, CSRF protection, rate limiting, secure cookies.

## Quick Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```
UI (dev):
```bash
cd sentinel-mind
npm install
npm run dev
# open http://localhost:8080/
```

## Configuration
Environment (`.env`) supports:
```env
# Core
OPENAI_API_KEY=
DATABASE_URL=sqlite+aiosqlite:///./soc_agent.db
AGENT_AUTONOMY_LEVEL=high
LEARNING_ENABLED=true
MAX_PARALLEL_INVESTIGATIONS=10
HOST=0.0.0.0
PORT=8000

# Integrations
EDR_ENDPOINT=http://localhost:8001
SIEM_ENDPOINT=http://localhost:8002
THREAT_INTEL_ENDPOINT=http://localhost:8003

# Auth & Sessions
SECRET_KEY=change_me
SESSION_EXP_MINUTES=30
COOKIE_SECURE=false            # true in production (HTTPS)
ADMIN_USERNAME=admin           # bootstrap admin (optional)
ADMIN_PASSWORD=admin123        # bootstrap admin (optional)
ADMIN_EMAIL=admin@example.com  # optional

# Threat Response
SEVERITY_THRESHOLD=7.0
REPORT_FORMAT=json
PROTOCOL_ID=EMERGENCY-001
TIMESTAMP_FORMAT=%Y-%m-%dT%H:%M:%S
SECURITY_STANDARD=ISO27001
```
Frontend:
- `VITE_API_BASE_URL` defaults to `/api` and proxies to backend in dev.

## Running
### Dev Servers
- API: `python main.py` → `http://localhost:8000/`
- UI: `npm run dev` → `http://localhost:8080/`

### Docker
```bash
docker compose up -d --build
```
- UI: `http://localhost:8080/`
- API: `http://localhost:8000/`
Enable TLS on your reverse proxy and set `COOKIE_SECURE=true`.

## API Reference
- Health
  - `GET /health`
- Alerts
  - `POST /alerts` — ingest alert
  - `POST /alerts/async` — async ingest
  - `GET /alerts/{id}` — result
  - `POST /alerts/{id}/feedback` — learning feedback
  - `GET /alerts` — recent alerts (UI data)
  - `POST /alerts/example` — test alert
- Investigations & Activity
  - `GET /investigations` — recent investigations (UI data)
  - `GET /activity` — activity feed (UI data)
  - `GET /stats` — agent metrics
- Admin Auth
  - `GET /auth/csrf` — set CSRF cookie
  - `POST /auth/login` — username/password; admin-only session cookie
  - `POST /auth/logout` — clears session; requires `X-CSRF-Token`
  - `GET /auth/me` — admin session validation
- Incidents & Response
  - `GET /incidents` — list incidents/actions/access logs (admin)
  - `POST /respond/{alert_id}/replay` — re-run response on stored alert (admin)
  - `POST /monitor/alert` — continuous monitoring input (servers/devices/networks/websites)

Examples:
```bash
# Ingest alert
curl -X POST http://localhost:8000/alerts -H "Content-Type: application/json" -d '{"title":"Suspicious","source":"edr","severity":"high","hostname":"wkst-01","user_id":"u1"}'

# Monitoring alert
curl -X POST http://localhost:8000/monitor/alert -H "Content-Type: application/json" -d '{"server_name":"srv-01","user_id":"alice","ip_address":"10.0.0.5","alert_type":"network","severity":"medium","threat_type":"scan","network_segment":"seg-a"}'

# Admin auth flow
curl -c cookies.txt http://localhost:8000/auth/csrf
CSRF=$(grep csrf_token cookies.txt | awk '{print $7}')
curl -b cookies.txt -c cookies.txt -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" -d '{"username":"admin","password":"admin123"}' http://localhost:8000/auth/login
curl -b cookies.txt http://localhost:8000/incidents
```

## Admin Dashboard
- `http://localhost:8080/login` — login page (CSRF protected)
- `http://localhost:8080/admin` — protected admin dashboard
- Dashboard shows alerts, investigations, activity; incidents API can be added to UI.
- Logout sends CSRF-protected request; session cookies are HttpOnly and SameSite=Strict.

## Security
- Authentication: bcrypt hashed passwords, admin-only access.
- Session: JWT in HttpOnly cookie with configurable expiry; `COOKIE_SECURE` for HTTPS.
- CSRF: double-submit cookie; state-changing endpoints require `X-CSRF-Token`.
- Rate limiting: per-IP login attempts; DB lockout after repeated failures.
- Cookies: `HttpOnly`, `SameSite=Strict`, `Secure` (in production).
- Audit trail: chained hashes across response actions to preserve chain of custody.
- Compliance: incident reports include `SECURITY_STANDARD`; timestamps follow `TIMESTAMP_FORMAT`.

## Architecture
```
Alert → Classification → Investigation → Decision → Conclusion → Auto-Response
                         ↘ Learning (risk adjustment) ↗
Storage: Alerts, Investigations, Incidents, Actions, Audit Trail
Admin: Auth, CSRF, Rate-Limiting, Access Logs
UI: Dashboard (alerts/investigations/activity), Admin login/protected routes
```

## Development
Project Structure:
```
soc-ai-agent/
├── api.py                 # FastAPI application & endpoints
├── agent.py               # Orchestrator
├── alert_processor.py     # Ingestion & classification
├── investigation_engine.py# Investigations
├── decision_maker.py      # Decisions
├── conclusion_generator.py# Conclusions
├── response.py            # Tiered auto-response & persistence
├── learning_system.py     # Learning & metrics
├── models.py              # Pydantic models
├── database.py            # SQLAlchemy models/sessions
├── config.py              # Settings
├── main.py                # Entry point
├── sentinel-mind/         # React UI (Vite + shadcn)
└── requirements.txt
```
Customize:
- New data sources: add endpoints in `config.py`, query in `investigation_engine.py`.
- Decision policy: tune `decision_maker.py` thresholds and actions.
- UI: use `React Query` to extend admin views (incidents/actions).

## Version History
- 1.0.0 — Initial: ingestion, investigation, decisions, conclusions, learning, basic UI.
- 1.1.0 — Added admin auth, CSRF, rate limiting, secure cookies, incidents/response manager, monitoring endpoint, Docker/Compose.

## Contributing
- Fork and create feature branches.
- Write tests or verification steps for endpoints and UI changes.
- Open a PR with a clear description and minimal scope.

## License
Provided as-is for demonstration purposes.
