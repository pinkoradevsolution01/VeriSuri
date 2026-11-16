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

## Setup

1. Apply [schema.sql](supabase/schema.sql) in the Supabase SQL editor.
2. Apply [20261116_production_readiness.sql](supabase/migrations/20261116_production_readiness.sql) immediately after it. This installs the consent-recording, profile, moderation, and deletion-request workflow used by the PWA.
3. Put `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and `GOOGLE_WEB_RISK_API_KEY` in Vercel server environment variables only—never client `VITE_` variables.
4. Train `backend/train.py` only on permissioned labelled Filipino, English, and Taglish messages. Model artifacts are deliberately ignored by Git.
5. Configure Google/Facebook Auth redirect URLs in Supabase, appoint moderators, and assign each moderator or admin a role in `public.profiles`.
6. Before public production intake, complete the organization privacy notice with a DPO contact, obtain legal/privacy review, add rate limiting, malware scanning, and signed evidence uploads.

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

## Delivery status

The MVP foundations are implemented: app UI, FastAPI endpoint contract, local rule engine, trainable scikit-learn model pipeline, Web Risk integration boundary, report-match repository, Supabase schema/RLS, and Vercel configuration. Evidence vault, Scam DNA, map, web push, ONNX, and transformer features remain separately scoped Phase 2–4 work.
