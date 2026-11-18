# VeriSuri

Philippine-focused PWA scam prevention. It uses a local Python/scikit-learn hybrid engine and does not send messages to Gemini or OpenAI.

## Local development

```powershell
npm.cmd install
npm.cmd run dev
```

In a second terminal:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
uvicorn backend.app.main:app --reload --port 8000
```

For split local development, make `.env.local` with `VITE_API_BASE_URL=http://localhost:8000/api/v1`.

## Vercel deployment

Import the repository as **one Vite project** from its root directory. Do not choose the multi-service import: the root [`vercel.json`](vercel.json) already builds the Vite PWA, routes `/api/*` to [`api/index.py`](api/index.py), and preserves client-side routes. The root [`requirements.txt`](requirements.txt) installs the FastAPI runtime dependencies for that Python function.

In the import screen, choose **Import single project** beside the Vite application, use root directory `./`, and keep the Framework Preset as **Vite**. Add server-only environment variables there, then deploy.

The root [`.python-version`](.python-version) pins Vercel's FastAPI function to Python 3.12. Keep this file: the pinned Pydantic and scikit-learn dependencies are compatible with Python 3.12, while the current Python 3.14 build image is not.

## Setup

1. Apply [schema.sql](supabase/schema.sql) in the Supabase SQL editor.
2. Apply [20261116_production_readiness.sql](supabase/migrations/20261116_production_readiness.sql) immediately after it. This installs the consent-recording, profile, moderation, and deletion-request workflow used by the PWA.
3. Put `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and `GOOGLE_WEB_RISK_API_KEY` in Vercel server environment variables only—never client `VITE_` variables.
4. Train `backend/train.py` only on permissioned labelled Filipino, English, and Taglish messages. Model artifacts are deliberately ignored by Git.
5. Configure Google/Facebook Auth redirect URLs in Supabase, appoint moderators, and assign each moderator or admin a role in `public.profiles`.
6. Before public production intake, complete the organization privacy notice with a DPO contact, obtain legal/privacy review, add rate limiting, malware scanning, and signed evidence uploads.

## Subscription plans and URL-scan allocation

1. Apply [20261117_subscription_and_url_quotas.sql](supabase/migrations/20261117_subscription_and_url_quotas.sql), then [20261117_url_scan_abuse_protection.sql](supabase/migrations/20261117_url_scan_abuse_protection.sql), after the earlier Supabase migrations.
2. Set `FREE_WEB_RISK_MONTHLY_BUDGET=100000` in local `.env` and Vercel server variables. It is a configurable product allocation, not a replacement for Google Cloud billing controls.
3. Free is **₱0/month**. A signed-in Free member can receive up to fifteen Google Web Risk URL checks per Philippine calendar day. The backend recalculates the actual cap atomically from the allocation left, active Free members, and days left in the month; it can fall below fifteen, including zero, rather than exceeding the allocation. Repeated URLs do not use another Google lookup; three unique URLs in five minutes pauses Google lookups for thirty minutes while local rules remain available.
4. Pro is **₱79/month** with a 30-check daily allowance after verified payment. Premium is **₱149/month** with a 100-check daily allowance after verified payment.
5. Selecting Pro or Premium records a payment request only. It does not activate a paid allowance until a future payment-provider webhook verifies payment. Do not bypass this with browser-side updates.

## Permissioned data workflow

- A normal scam report does **not** authorize model training.
- A contributor must separately opt in and provide a redacted sample. It enters `training_examples` as `pending`.
- A moderator must confirm the underlying report and approve the sample before it becomes eligible for offline export and model evaluation.
- A deletion request immediately withdraws pending opted-in samples; a privacy reviewer must complete the request according to the organization retention policy.

## AI model workflow

1. Review and approve permissioned labelled data against [`backend/data/README.md`](backend/data/README.md).
2. Train: `py backend/train.py backend/data/approved_messages.csv --version verisuri-hybrid-v1`.
3. Gate the result: `py backend/evaluate.py backend/models/verisuri_v1.metrics.json`.
4. Register approved metrics: `py backend/register_model.py backend/models/verisuri_v1.metrics.json`.

## Before You Pay: production configuration

### Zero-fee starting architecture

VeriSuri starts every URL assessment with local Python rules and two server-side threat sources:

- **PhishDestroy CTI:** the default live domain-reputation check. No key is required. VeriSuri sends only the normalized hostname, caches each result for 15 minutes, and applies a server-wide 30-request-per-minute ceiling before calling the public API. Attribute it as `PhishDestroy CTI, https://phishdestroy.io, accessed YYYY-MM-DD` in public product materials.
- **CERT Polska Warning List:** requires no key. Its active-domain feed is refreshed in memory by FastAPI.
- **PhishTank (optional):** if legitimate new registrations become available, set `PHISHTANK_APP_KEY` for its verified-online feed. VeriSuri does not require it.
- **Python detection engine:** detects URL structure, lookalike financial brands, suspicious domain endings, credential lures, and other explainable signals.

The browser never calls any feed directly. Feed matches are evidence only; a no-match result is not a safety guarantee. `THREAT_FEED_REFRESH_MINUTES=60` controls the CERT Polska and optional PhishTank refresh interval. Do not put `PHISHTANK_APP_KEY` in a Vite variable.

Google Web Risk remains integrated but is disabled by default. Set `ENABLE_GOOGLE_WEB_RISK=true` only after its billing account is active; this preserves the existing quota and abuse-protection logic for a future commercial release.

1. In Google Cloud, enable billing and the **Web Risk API** for the project that will run VeriSuri. Create an API key restricted to the Web Risk API. Keep it server-side only.
2. Add `GOOGLE_WEB_RISK_API_KEY` to the local FastAPI `.env` for development and to Vercel's server environment variables for production. Do not add it to `.env.local` or any `VITE_` variable.
3. Submit a real report through VeriSuri, sign in as an assigned moderator, and confirm the report. Only confirmed records can be returned by payment/report matching.
4. Restart FastAPI, then validate the live integration using that confirmed identifier:

```powershell
.\.venv\Scripts\python.exe backend\validate_before_you_pay.py --identifier "THE-CONFIRMED-IDENTIFIER" --entity-type gcash --access-token "SIGNED-IN-SUPABASE-ACCESS-TOKEN"
```

The validation command verifies both the confirmed Supabase match and, unless `--skip-web-risk` is supplied, Google's official Web Risk test-list URL through an authenticated subscription allowance. Never commit or share the access token. It never creates fake reports or inserts test intelligence.

## Delivery status

The MVP foundations are implemented: app UI, FastAPI endpoint contract, local rule engine, trainable scikit-learn model pipeline, Web Risk integration boundary, report-match repository, Supabase schema/RLS, and Vercel configuration. Evidence vault, Scam DNA, map, web push, ONNX, and transformer features remain separately scoped Phase 2–4 work.
