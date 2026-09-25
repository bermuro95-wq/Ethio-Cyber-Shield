# Ethio-Cyber Shield (ECS)

**Homegrown Cybersecurity MVP for INSA Ethiopia Competition**

A real, simple, working cybersecurity platform for recording incidents, threat indicators, fraud detection, risk scoring, alerts, and audit logging.

## Stack (Strictly as Specified)

| Layer       | Technology              |
|-------------|-------------------------|
| Backend     | Python (Flask)          |
| Frontend    | HTML5 + CSS3 + Vanilla JS + Bootstrap 5 |
| Database    | Supabase (PostgreSQL)   |
| Deployment  | Frontend → Netlify<br>Backend → Render / Railway / any Python host |

**No React. No AI. No ML. No fake data. Real Supabase.**

### Why there is no Supabase JS on the frontend

All database access goes through the **Python backend** (`supabase-py`).  
This is intentional and more secure:

- Service role key and JWT secret stay on the server only  
- Security rules, fraud detection, risk scoring and audit logging run server-side  
- Frontend never talks directly to Supabase (no exposed keys)

Flow:
```
HTML / Vanilla JS  →  Python API  →  Supabase PostgreSQL
```

You do **not** need `@supabase/supabase-js` in the browser for this architecture.

---

## Features

1. **Secure Login** – JWT auth, roles: Admin / Analyst / Viewer
2. **Incident Management** – CRUD, search, filter, types (phishing, ATO, fraud, malware…)
3. **Threat Indicators (IOCs)** – IP, Domain, URL, Email, File Hash + status
4. **Rule-based Security Analysis** – risk score with transparent reasons
5. **Simple Fraud Detection** – high amount, burst, multi-account device rules
6. **Cyber ↔ Fraud Correlation** – time proximity + IP matching
7. **Risk Levels** – Low / Medium / High / Critical with reasons
8. **Alerts** – auto-created, acknowledge, resolve
9. **Live Dashboard** – real counts from Supabase
10. **Immutable Audit Log**

---

## Quick Start

### 1. Supabase Setup

1. Create a project at [supabase.com](https://supabase.com)
2. Go to **SQL Editor** → paste and run `sql/schema.sql`
3. Copy **Project URL**, **anon key**, and **service_role key** from Settings → API

### 2. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your Supabase keys and a strong JWT_SECRET
python run.py
```

API runs at `http://localhost:5000`

Default admin (after schema seed):
- Email: `admin@ethiocybershield.et`
- Password: `Admin@123`  
**Change this immediately in production.**

### 3. Frontend

```bash
cd frontend
# Update js/config.js → API_BASE_URL to your backend URL
# Serve locally for testing:
npx serve . -p 5500
# or use any static server / VS Code Live Server
```

Open `http://localhost:5500/login.html`

### 4. Deploy

**Frontend (Netlify)**  
- Drag & drop the `frontend` folder, or connect Git repo  
- Set publish directory to `frontend` (or root if you upload only frontend)  
- Update `js/config.js` with production API URL before deploy

**Backend (Render free tier example)**  
- New Web Service → connect repo or upload  
- Build: `pip install -r requirements.txt`  
- Start: `gunicorn -b 0.0.0.0:$PORT run:app` (from backend folder)  
- Add environment variables from `.env.example`

---

## Demo Workflow

1. Login as admin  
2. Create an Incident (e.g. Phishing, High severity)  
3. Add a Malicious Indicator (IP or URL)  
4. Link indicator to the incident  
5. Click **Run Analysis** → risk score + reasons appear  
6. Add a high-value Transaction (e.g. 600 000 ETB) on a new device  
7. System flags it and creates an Alert  
8. View Dashboard (real numbers)  
9. Check Audit Log  

Every step uses the real database.

---

## Project Structure

```
ethio-cyber-shield/
├── backend/
│   ├── app/
│   │   ├── routes/          # API endpoints
│   │   ├── services/        # auth, rules, audit, db
│   │   ├── config.py
│   │   └── __init__.py
│   ├── requirements.txt
│   ├── run.py
│   └── .env.example
├── frontend/
│   ├── css/style.css
│   ├── js/                  # config, api, common
│   ├── *.html               # pages
│   └── netlify.toml
├── sql/schema.sql
└── README.md
```

---

## Security Notes

- Passwords hashed with bcrypt  
- JWT tokens with expiry  
- Role-based authorization on every mutating endpoint  
- Input validation & basic sanitization  
- Secrets only in environment variables  
- Audit log is append-only (no update/delete endpoints)  
- CORS restricted to configured origins  

---

## License & Attribution

Built as a homegrown Ethiopian cybersecurity MVP for the INSA competition.  
Keep it real. Keep it simple. Keep it working.

**Ethio-Cyber Shield** – Protecting digital Ethiopia.
