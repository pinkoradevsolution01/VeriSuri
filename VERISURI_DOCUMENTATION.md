# VeriSuri Application Documentation

## Product overview

VeriSuri is a Philippine-focused progressive web application for scam prevention and digital-safety support. It is designed for iOS, Android, and desktop browsers, with an installable PWA experience and a responsive interface.

The application is centred on **Check Before You Pay**: helping users review suspicious messages, links, payment requests, and moderated community reports before taking action. VeriSuri presents risk signals, clear recommendations, verified official-contact paths, incident-recovery guidance, and privacy-aware community reporting.

## What users can do

- Review payment requests before sending money through GCash, Maya, banks, or other payment channels.
- Analyze suspicious English, Filipino, and Taglish messages for scam indicators.
- Check a URL using normalized URL analysis, Python detection rules, public threat intelligence, and moderated community evidence.
- Search moderated scam reports without exposing contributor identities or full payment identifiers.
- Submit structured scam reports with provider, scam type, channel, amount range, time, suspicious URL or number, and optional redacted evidence.
- Follow a guided recovery flow after sending money or sharing an OTP.
- Open provider help channels from VeriSuri’s official-contact directory.
- Store redacted evidence, references, timestamps, and notes in a private Evidence Vault.
- View moderated safety alerts with source, review information, affected platform, and expiry details.
- Sign in with email magic link, Google, or Facebook through Supabase Auth.
- Manage account security preferences, sessions, and authenticator-app MFA where enabled.

## User experience and navigation

VeriSuri uses a desktop-first application layout that adapts to tablets and phones.

| Screen size | Navigation approach |
| --- | --- |
| Desktop | Header navigation for Overview, Dashboard, Report Lookup, Safety Alerts, Report Incident, account controls, and moderator tools where authorized. |
| Mobile and tablet | A fixed bottom navigation for Home, Check, Reports, Alerts, and More. The More menu provides the complete route list, recovery flow, Evidence Vault, account security, moderation tools for authorized users, and accessibility settings. |

The interface includes keyboard focus styling, reduced-motion support, high-contrast preferences, scalable text, safe-area handling for iOS, responsive touch controls, and PWA installation support.

## Safety workflow

### 1. Check

The user pastes a message or URL, or enters a payment identifier. VeriSuri sends the request to the FastAPI backend through its `/api/v1` interface.

### 2. Assess

The detection service combines relevant evidence sources:

- URL normalization and Python URL rules
- Financial-brand lookalike and credential-lure indicators
- CERT Polska malicious-domain intelligence
- PhishDestroy CTI domain reputation
- Optional Google Web Risk integration
- Optional PhishTank intelligence integration
- Moderated community report matching
- VeriSuri message indicators and the registered custom model workflow

### 3. Explain

Each result includes a visual risk score, severity treatment, evidence confidence, warning signs, matching sources, and an action-oriented recommendation.

### 4. Act safely

High- and medium-risk results provide a Scam Action Plan that guides users to stop the transaction, avoid sharing credentials or OTPs, save evidence, contact the provider through verified official channels, and submit an incident report when appropriate.

## Software stack

| Layer | Technology | Purpose |
| --- | --- | --- |
| Frontend | React, TypeScript, Vite | Responsive single-page PWA interface. |
| Styling | CSS, Tailwind CSS tooling, PostCSS, Autoprefixer | Responsive design, mobile safe-area support, accessible visual states, and production CSS processing. |
| Icons | Lucide React | Consistent interface and safety-action icons. |
| PWA | Web App Manifest and Service Worker | Installation support and app-shell caching for supported browsers. |
| Backend | Python 3.12 and FastAPI | Server-side API, screening orchestration, authentication-aware workflows, and secure integrations. |
| AI engine | scikit-learn, NumPy, joblib | Hybrid Philippine scam-message classification workflow using character-level TF-IDF, logistic regression, and a fraud-indicator rules engine. |
| Database and identity | Supabase PostgreSQL and Supabase Auth | Profiles, roles, reports, moderation, usage controls, evidence metadata, sessions, OAuth, and magic-link authentication. |
| Access control | PostgreSQL Row Level Security and role-based access control | Privacy-aware user records, moderator workflows, and administrative protection. |
| Threat intelligence | CERT Polska, PhishDestroy CTI, optional Google Web Risk, optional PhishTank, and moderated community data | URL and domain evidence used by the screening service. |
| Hosting | Vercel | Vite frontend hosting, FastAPI serverless API route, rewrites, and production deployment. |
| Future AI delivery | ONNX Runtime Web, PyTorch, and multilingual Transformers | Offline screening and advanced multilingual model delivery. |

## System architecture

```text
VeriSuri PWA
  React + TypeScript + Vite
          |
          v
Vercel
  Static frontend + /api rewrite
          |
          v
FastAPI screening service
  Message analysis | Link analysis | Before You Pay | Report matching
          |
          +--> VeriSuri Python detection engine
          +--> Threat-intelligence providers
          +--> Supabase PostgreSQL and Storage
          +--> Supabase Auth and role controls
```

## Core application modules

| Module | Main capability | Main technologies |
| --- | --- | --- |
| Overview | Product introduction, how-it-works content, plan selection, and verified alert preview | React, TypeScript, CSS |
| Dashboard | Entry point for protection tools and incident response | React, Lucide React |
| Before You Pay | Payment identifier checks and moderated-report matching | FastAPI, Supabase PostgreSQL |
| AI Message Analysis | Message indicators, explainability, score, and action plan | Python, scikit-learn workflow, FastAPI |
| Suspicious Link Checker | URL normalization, reputation lookups, local rules, and risk explanation | FastAPI, CERT Polska, PhishDestroy CTI, Google Web Risk integration |
| Scam Reports Lookup | Restricted matching against confirmed reports | Supabase PostgreSQL, Row Level Security |
| Report Incident | Structured report submission and moderation handoff | React, Supabase |
| Moderation | Review queues, approval actions, audit-aware administration, and alert publication | React, Supabase roles and policies |
| Evidence Vault | Redacted evidence references, notes, timestamps, and incident preparation | Supabase storage and PostgreSQL metadata |
| Incident Recovery | Urgent post-incident checklist and official support paths | React, official-contact directory |
| Safety Alerts | Published advisories with source and review details | FastAPI, Supabase |
| Account Security | Authenticator-app MFA, session management, activity review, and staff controls | Supabase Auth, PostgreSQL |

## Data model

The Supabase database supports the following application areas:

- `profiles` for account information, roles, subscription state, and user preferences.
- `scan_results` for saved safety assessments.
- `scam_reports` for structured community incident reports.
- `report_evidence` for private evidence references and attachments.
- `reported_entities` for URLs, payment identifiers, numbers, and other report indicators.
- `fraud_cases` for recovery-case management.
- `fraud_alerts` for published scam advisories.
- `moderation_actions` for review decisions and appeals.
- `model_versions` for model release records and evaluation data.
- `audit_logs` for sensitive administrative activity.
- `web_risk_daily_usage` and abuse-protection records for URL-scan allocation.
- MFA, session, Evidence Vault, recovery, moderated-alert, structured-report, and external-threat-observation tables added by the project migrations.

All user and moderator access is governed by Supabase Row Level Security policies and role-based database rules.

## AI and model lifecycle

VeriSuri’s model workflow is designed around permissioned and moderated Philippine scam and legitimate-message data.

1. Collect redacted, consented, labelled Filipino, English, and Taglish messages.
2. Review and approve eligible data for offline training.
3. Train the hybrid model with `backend/train.py`.
4. Evaluate model metrics using `backend/evaluate.py`.
5. Record accountable approval through `backend/approve_model.py`.
6. Register the approved version with `backend/register_model.py`.
7. Deploy the registered model through FastAPI.
8. Continue improvement with moderated, permissioned data and model-version records.

The detection design supports transparent evidence: warning signs, threat-source matches, report matches, and model-related indicators are shown to the user as part of the result experience.

## Authentication and account security

Supabase Auth supports these sign-in routes:

- Email magic link
- Google OAuth
- Facebook OAuth

Account protection includes protected sessions, account activity, device/session controls, optional authenticator-app MFA, staff enforcement for sensitive moderation actions, and role-based access for users, moderators, and administrators.

## Subscription plans

| Plan | Price | Daily URL scans |
| --- | ---: | ---: |
| Free | ₱0/month | Up to 15 scans per day through the shared allocation flow |
| Pro | ₱79/month | Up to 30 scans per day after payment verification |
| Premium | ₱149/month | Up to 100 scans per day after payment verification |

The backend manages daily allowance, monthly allocation, repeated-URL reuse, and abuse-protection rules server-side. Plan selection and account state are stored in the authenticated user profile.

## Environment configuration

Use `.env` for backend-only local variables and `.env.local` for Vite variables. Do not place server secrets in browser-exposed `VITE_` variables.

| Variable | Used by | Purpose |
| --- | --- | --- |
| `VITE_API_BASE_URL` | Frontend | Base address for the FastAPI `/api/v1` service during local development. |
| `VITE_SUPABASE_URL` | Frontend | Supabase project URL. |
| `VITE_SUPABASE_ANON_KEY` | Frontend | Supabase public anonymous key. |
| `SUPABASE_URL` | Backend | Supabase project URL for server actions. |
| `SUPABASE_SERVICE_ROLE_KEY` | Backend | Server-only Supabase administrative access. |
| `GOOGLE_WEB_RISK_API_KEY` | Backend | Server-only Google Web Risk integration key. |
| `ENABLE_GOOGLE_WEB_RISK` | Backend | Enables the Google Web Risk provider. |
| `PHISHTANK_APP_KEY` | Backend | Optional PhishTank provider key. |
| `THREAT_FEED_REFRESH_MINUTES` | Backend | Threat-feed refresh interval. |
| `FREE_WEB_RISK_MONTHLY_BUDGET` | Backend | Monthly allocation used by the Free URL-scan plan. |

## Local development

### Frontend

```powershell
npm.cmd install
npm.cmd run dev
```

### Backend

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --port 8000
```

The frontend runs on Vite and communicates with FastAPI through the configured `VITE_API_BASE_URL`.

### Build validation

```powershell
npm.cmd run build
```

## Database deployment

Apply the database schema and project migrations in the Supabase SQL Editor. Run the base schema first, then apply the migration files in chronological order from `supabase/migrations`.

The migrations provision production-ready records for consent, subscriptions, daily URL usage, abuse protection, Evidence Vault, incident recovery, moderated alerts, structured reporting, MFA, account security, and external threat observations.

## Vercel deployment

Deploy the repository as one Vite project from the root directory.

- Framework preset: **Vite**
- Root directory: `./`
- Build command: `npm run build`
- Output directory: `dist`
- API route: `/api/*` is rewritten to `api/index.py`
- Client routes: all remaining routes are rewritten to `index.html`
- Python runtime: Python 3.12, defined by `pyproject.toml` and `.python-version`

Add backend environment variables in Vercel Project Settings before deployment. Vercel hosts the frontend and FastAPI API within the same project configuration.

## Development roadmap

| Stage | Focus |
| --- | --- |
| Foundation | Responsive PWA, professional user interface, Supabase authentication, account security, and Vercel deployment. |
| AI Engine | Permissioned data lifecycle, hybrid scam detection model, evaluation, approval, and version registration. |
| Before You Pay | Payment checks, message analysis, URL intelligence, and moderated-report matching. |
| Community Reporting | Structured reports, redacted evidence, moderation, audit records, and published advisories. |
| Recovery and Intelligence | Evidence Vault, Scam DNA, report-relationship analysis, and recovery support. |
| Nationwide Expansion | Regional alerts, aggregated intelligence map, multilingual intelligence, and offline screening. |

## Repository structure

```text
src/                 React PWA interface, components, styles, and client libraries
backend/             FastAPI app, screening engine, model scripts, and datasets
api/                 Vercel FastAPI entry point
supabase/            Base schema and database migrations
public/              PWA manifest, service worker, and static assets
vercel.json          Vercel build and route configuration
pyproject.toml       Python 3.12 runtime and server dependency configuration
```
