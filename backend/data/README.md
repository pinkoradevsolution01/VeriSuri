# Permissioned training data contract

Never add user submissions, OTPs, account numbers, or raw private conversations without explicit lawful permission and privacy review.

The local training CSV must be UTF-8 and contain:

```text
text,label,language,scam_type,source,consent_reference,moderation_reference
"Your account is blocked...",1,en,phishing,permissioned-research,consent-001,moderation-001
"Salamat sa inyong order",0,fil,legitimate,permissioned-research,consent-002,moderation-002
```

- `label`: `1` means scam/fraud signal; `0` means legitimate.
- `language`: `en`, `fil`, or `taglish` enables fairness checks.
- `source` and `consent_reference` document authorization and auditability.
- `moderation_reference` records the human review that approved the row for model evaluation.
- `scam_type` is `legitimate` for label `0`; label `1` uses one of `phishing`, `impersonation`, `investment`, `marketplace`, `job`, `loan`, `delivery`, `romance`, or `other`.

## Release-candidate gate

The trainer now rejects synthetic data, duplicate messages, missing consent/moderation references, and datasets with fewer than 300 rows. It requires representation for `en`, `fil`, and `taglish`, both classes in each language, and at least 50 reviewed scam records for every supported scam type. This is a minimum validation floor, not proof of nationwide accuracy.

Train only after data approval:

```powershell
.\.venv\Scripts\python.exe backend\train.py backend\data\approved_messages.csv --version verisuri-hybrid-v1
.\.venv\Scripts\python.exe backend\evaluate.py backend\models\verisuri_v1.metrics.json
.\.venv\Scripts\python.exe backend\approve_model.py backend\models\verisuri_v1.metrics.json --reviewer "reviewer-id"
.\.venv\Scripts\python.exe backend\register_model.py backend\models\verisuri_v1.metrics.json
```

The evaluator blocks release candidates unless overall, per-language, and per-scam-type held-out precision, recall, F1, and false-positive rate meet the declared gates. The model will not load in VeriSuri until its metrics are marked `approved`.

## Continuous improvement without automatic retraining

Never retrain directly from live user reports. A new candidate may be trained only after records have explicit model-training permission, sensitive details have been redacted, a moderator has approved each row, and the full validation/evaluation/approval sequence above completes again. The previous approved model remains active until a human reviewer approves the replacement.

For a pipeline smoke test only, run `py backend/generate_demo_dataset.py` and train against `backend/data/synthetic_demo_messages.csv`. This synthetic output is intentionally excluded from Git and must never be registered or deployed as a production model.

## URL phishing model contract

The URL model is separate from the message model. Its UTF-8 CSV requires:
url,label,scam_type,source,consent_reference,moderation_reference.
Use phishing for a scam URL and legitimate for a legitimate URL.

The trainer requires at least 500 permissioned, moderated URLs with at least
150 phishing and 150 legitimate records. It writes a candidate only. The model
stays disabled until its held-out precision, recall, F1, calibration, and
false-positive-rate gates pass and a named reviewer approves it:

    python -m backend.train_url_model backend/data/approved_urls.csv --version verisuri-url-v1
    python -m backend.approve_url_model backend/models/verisuri_url_v1.metrics.json --reviewer "reviewer-id"

Never train this model from unreviewed reports or synthetic examples.
